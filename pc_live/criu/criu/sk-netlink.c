#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libnl3/netlink/msg.h>

#include "imgset.h"
#include "files.h"
#include "sockets.h"
#include "util.h"

#include "protobuf.h"
#include "images/sk-netlink.pb-c.h"
#include "netlink_diag.h"
#include "libnetlink.h"
#include "namespaces.h"
#include "prestore.h"

#undef LOG_PREFIX
#define LOG_PREFIX "netlink: "

struct netlink_sk_desc {
	struct socket_desc sd;
	u32 portid;
	u32 *groups;
	u32 gsize;
	u32 dst_portid;
	u32 dst_group;
	u8 state;
	u8 protocol;
};

int netlink_receive_one(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	struct nlattr *tb[NETLINK_DIAG_MAX + 1];
	struct netlink_diag_msg *m;
	struct netlink_sk_desc *sd;
	unsigned long *groups;

	m = NLMSG_DATA(hdr);
	pr_debug("Collect netlink sock 0x%x\n", m->ndiag_ino);

	sd = xmalloc(sizeof(*sd));
	if (!sd)
		return -1;

	sd->protocol = m->ndiag_protocol;
	sd->portid = m->ndiag_portid;
	sd->dst_portid = m->ndiag_dst_portid;
	sd->dst_group = m->ndiag_dst_group;
	sd->state = m->ndiag_state;

	nlmsg_parse(hdr, sizeof(struct netlink_diag_msg), tb, NETLINK_DIAG_MAX, NULL);

	if (tb[NETLINK_DIAG_GROUPS]) {
		sd->gsize = nla_len(tb[NETLINK_DIAG_GROUPS]);
		groups = nla_data(tb[NETLINK_DIAG_GROUPS]);

		sd->groups = xmalloc(sd->gsize);
		if (!sd->groups) {
			xfree(sd);
			return -1;
		}
		memcpy(sd->groups, groups, sd->gsize);
	} else {
		sd->groups = NULL;
		sd->gsize = 0;
	}

	return sk_collect_one(m->ndiag_ino, PF_NETLINK, &sd->sd, ns);
}

static bool can_dump_netlink_sk(int lfd)
{
	int ret;

	ret = fd_has_data(lfd);
	if (ret == 1)
		pr_err("The socket has data to read\n");

	return ret == 0;
}

static int dump_one_netlink_fd(int lfd, u32 id, const struct fd_parms *p)
{
	struct netlink_sk_desc *sk;
	FileEntry fe = FILE_ENTRY__INIT;
	NetlinkSkEntry ne = NETLINK_SK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;

	sk = (struct netlink_sk_desc *)lookup_socket(p->stat.st_ino, PF_NETLINK, 0);
	if (IS_ERR(sk))
		goto err;

	ne.id = id;
	ne.ino = p->stat.st_ino;

	if (!can_dump_netlink_sk(lfd))
		goto err;

	if (sk) {
		BUG_ON(sk->sd.already_dumped);

		ne.ns_id = sk->sd.sk_ns->id;
		ne.has_ns_id = true;
		ne.protocol = sk->protocol;
		ne.portid = sk->portid;
		ne.groups = sk->groups;

		ne.n_groups = sk->gsize / sizeof(ne.groups[0]);
		/*
		 * On 64-bit sk->gsize is multiple to 8 bytes (sizeof(long)),
		 * so remove the last 4 bytes if they are empty.
		 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		/*
		 * Big endian swap: Ugly hack for zdtm/static/sk-netlink
		 *
		 * For big endian systems:
		 *
		 * - sk->groups[0] are bits 32-64
		 * - sk->groups[1] are bits 0-32
		 */
		if (ne.n_groups == 2) {
			uint32_t tmp = sk->groups[1];

			sk->groups[1] = sk->groups[0];
			sk->groups[0] = tmp;
		}
#endif
		if (ne.n_groups && sk->groups[ne.n_groups - 1] == 0)
			ne.n_groups -= 1;

		if (ne.n_groups > 1) {
			pr_err("%d %x\n", sk->gsize, sk->groups[1]);
			pr_err("The netlink socket 0x%x has more than 32 groups\n", ne.ino);
			return -1;
		}
		if (sk->groups && !sk->portid) {
			pr_err("The netlink socket 0x%x is bound to groups but not to portid\n", ne.ino);
			return -1;
		}
		ne.state = sk->state;
		ne.dst_portid = sk->dst_portid;
		ne.dst_group = sk->dst_group;
	} else { /* unconnected and unbound socket */
		struct ns_id *nsid;
		int val;
		socklen_t aux = sizeof(val);

		if (root_ns_mask & CLONE_NEWNET) {
			nsid = get_socket_ns(lfd);
			if (nsid == NULL)
				return -1;
			ne.ns_id = nsid->id;
			ne.has_ns_id = true;
		}

		if (getsockopt(lfd, SOL_SOCKET, SO_PROTOCOL, &val, &aux) < 0) {
			pr_perror("Unable to get protocol for netlink socket");
			goto err;
		}

		ne.protocol = val;
	}

	ne.fown = (FownEntry *)&p->fown;
	ne.opts = &skopts;

	if (dump_socket_opts(lfd, &skopts))
		goto err;

	fe.type = FD_TYPES__NETLINKSK;
	fe.id = ne.id;
	fe.nlsk = &ne;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE))
		goto err;

	return 0;
err:
	return -1;
}

const struct fdtype_ops netlink_dump_ops = {
	.type = FD_TYPES__NETLINKSK,
	.dump = dump_one_netlink_fd,
};

struct netlink_sock_info {
	NetlinkSkEntry *nse;
	struct file_desc d;
};

static int open_netlink_sk(struct file_desc *d, int *new_fd)
{
	struct netlink_sock_info *nsi;
	NetlinkSkEntry *nse;
	struct sockaddr_nl addr;
	int sk = -1;

	nsi = container_of(d, struct netlink_sock_info, d);
	nse = nsi->nse;

	pr_info("Opening netlink socket id %#x\n", nse->id);

	if (set_netns(nse->ns_id))
		return -1;

	sk = socket(PF_NETLINK, SOCK_RAW, nse->protocol);
	if (sk < 0) {
		pr_perror("Can't create netlink sock");
		return -1;
	}

	if (nse->portid) {
		memset(&addr, 0, sizeof(addr));
		addr.nl_family = AF_NETLINK;
		if (nse->n_groups > 1) {
			pr_err("Groups above 32 are not supported yet\n");
			goto err;
		}
		if (nse->n_groups)
			addr.nl_groups = nse->groups[0];
		addr.nl_pid = nse->portid;

		if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			/*
			 * Reassign if original bind fails, because socket addresses are
			 * typically kernel assigned based on PID, and collisions are common
			 * and very few applications care what address they are bound to.
			 */
			addr.nl_pid = 0;
			if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
				pr_perror("Can't bind netlink socket");
				goto err;
			}
			pr_warn("Netlink socket id %#x reassigned new port\n", nse->id);
		}
	}

	if (nse->state == NETLINK_CONNECTED) {
		addr.nl_family = AF_NETLINK;
		addr.nl_groups = 1 << (nse->dst_group - 1);
		addr.nl_pid = nse->dst_portid;
		if (connect(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			pr_perror("Can't connect netlink socket");
			goto err;
		}
	}

	if (rst_file_params(sk, nse->fown, nse->flags))
		goto err;

	if (restore_socket_opts(sk, nse->opts))
		goto err;

	*new_fd = sk;
	return 0;
err:
	close(sk);
	return -1;
}

static struct file_desc_ops netlink_sock_desc_ops = {
	.type = FD_TYPES__NETLINKSK,
	.open = open_netlink_sk,
};

// Function to check whether a netlink socket entry is already present from
// the previous iteration.
static int search_and_update_one_netlink_sk (ProtobufCMessage *base) {

    struct netlink_sock_info *si;
    NetlinkSkEntry *nse;
    struct file_desc *d;
    unsigned int id;
    int type;

    // Decode the image and get id & type.
    nse = pb_msg (base, NetlinkSkEntry);
    id = nse->id;
    type = (&netlink_sock_desc_ops)->type;

    // Search for this id and type.
    d = find_file_desc_raw (type, id);
    if (d != NULL) {
        si = container_of (d, struct netlink_sock_info, d);
        si->nse = nse;
        return 1;
    }

    // Not found.
    return 0;

}

static int collect_one_netlink_sk(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct netlink_sock_info *si = o;

	si->nse = pb_msg(base, NetlinkSkEntry);
	return file_desc_add(&si->d, si->nse->id, &netlink_sock_desc_ops);
}

struct collect_image_info netlink_sk_cinfo = {
	.fd_type = CR_FD_NETLINK_SK,
	.pb_type = PB_NETLINK_SK,
	.priv_size = sizeof(struct netlink_sock_info),
    .search_and_update = search_and_update_one_netlink_sk,
	.collect = collect_one_netlink_sk,
    .info_type = PRST_INFO_GLOBAL,
};
