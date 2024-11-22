#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/falloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <ctype.h>

#undef LOG_PREFIX
#define LOG_PREFIX "page-xfer: "

#include "types.h"
#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "page-xfer.h"
#include "page-pipe.h"
#include "util.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"
#include "fcntl.h"
#include "pstree.h"
#include "parasite-syscall.h"
#include "rst_info.h"
#include "stats.h"
#include "tls.h"

static int page_server_sk = -1;
static int xfer_server_sk = -1;
int prestore_started = 0;

struct page_server_iov {
	u32 cmd;
	u32 nr_pages;
	u64 vaddr;
	u64 dst_id;
    pid_t virt_pid;     // XXX: Shiv: Added to optimize memory consumptions during parallel restore.
};

static void psi2iovec(struct page_server_iov *ps, struct iovec *iov)
{
	iov->iov_base = decode_pointer(ps->vaddr);
	iov->iov_len = ps->nr_pages * PAGE_SIZE;
}

#define PS_IOV_ADD    1
#define PS_IOV_HOLE   2
#define PS_IOV_OPEN   3
#define PS_IOV_OPEN2  4
#define PS_IOV_PARENT 5
#define PS_IOV_ADD_F  6
#define PS_IOV_GET    7

#define PS_IOV_FLUSH	     0x1023
#define PS_IOV_FLUSH_N_CLOSE 0x1024

#define PS_CMD_BITS 16
#define PS_CMD_MASK ((1 << PS_CMD_BITS) - 1)

#define PS_TYPE_BITS 8
#define PS_TYPE_MASK ((1 << PS_TYPE_BITS) - 1)

#define PS_TYPE_PID   (1)
#define PS_TYPE_SHMEM (2)
/*
 * XXX: When adding new types here check decode_pm for legacy
 * numbers that can be met from older CRIUs
 */

static inline u64 encode_pm(int type, unsigned long id)
{
	if (type == CR_FD_PAGEMAP)
		type = PS_TYPE_PID;
	else if (type == CR_FD_SHMEM_PAGEMAP)
		type = PS_TYPE_SHMEM;
	else {
		BUG();
		return 0;
	}

	return ((u64)id) << PS_TYPE_BITS | type;
}

static int decode_pm(u64 dst_id, unsigned long *id)
{
	int type;

	/*
	 * Magic numbers below came from the older CRIU versions that
	 * erroneously used the changing CR_FD_* constants. The
	 * changes were made when we merged images together and moved
	 * the CR_FD_-s at the tail of the enum
	 */
	type = dst_id & PS_TYPE_MASK;
	switch (type) {
	case 10: /* 3.1 3.2 */
	case 11: /* 1.3 1.4 1.5 1.6 1.7 1.8 2.* 3.0 */
	case 16: /* 1.2 */
	case 17: /* 1.0 1.1 */
	case PS_TYPE_PID:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_PAGEMAP;
		break;
	case 27: /* 1.3 */
	case 28: /* 1.4 1.5 */
	case 29: /* 1.6 1.7 */
	case 32: /* 1.2 1.8 */
	case 33: /* 1.0 1.1 3.1 3.2 */
	case 34: /* 2.* 3.0 */
	case PS_TYPE_SHMEM:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_SHMEM_PAGEMAP;
		break;
	default:
		type = -1;
		break;
	}

	return type;
}

static inline u32 encode_ps_cmd(u32 cmd, u32 flags)
{
	return flags << PS_CMD_BITS | cmd;
}

static inline u32 decode_ps_cmd(u32 cmd)
{
	return cmd & PS_CMD_MASK;
}

static inline u32 decode_ps_flags(u32 cmd)
{
	return cmd >> PS_CMD_BITS;
}

static inline int __send (int sk, const void *buf, size_t sz, int fl) {

	int ret = opts.tls ? tls_send(buf, sz, fl) : send(sk, buf, sz, fl);
    int sent = (ret >= 0) ? ret : 0;
    total_sent_bytes += sent;
    return ret;

}

static inline int __recv(int sk, void *buf, size_t sz, int fl)
{
	return opts.tls ? tls_recv(buf, sz, fl) : recv(sk, buf, sz, fl);
}

static inline int send_psi_flags(int sk, struct page_server_iov *pi, int flags)
{
	if (__send(sk, pi, sizeof(*pi), flags) != sizeof(*pi)) {
		pr_perror("Can't send PSI %d to server", pi->cmd);
		return -1;
	}
	return 0;
}

static inline int send_psi(int sk, struct page_server_iov *pi)
{
	return send_psi_flags(sk, pi, 0);
}

/**
 * Shiv:
 * Function to send entire data (@buf+@size) to the xfer-server.
 * Return value:
 *      0   -> on success.
 *      -1  -> on some error.
 */
static inline int __send_all_buf (int sk, const void *buf, long int size
        , int flag) {

    long int ret = 0;
    long int left = size;

    // Send all data.
    while (left > 0) {
        //ret = __send (sk, (buf + ret), left, 0);
        ret = __send (sk, buf, left, 0);
        if (ret < 0) {
            pr_perror("Can't send data to the xfer-server (left: %ld)\n", left);
            return -1;
        }
        buf = buf + ret;
        left = left - ret;
    }
	return 0;

}

/**
 * Shiv:
 * Function to send complete file (@fd) to the xfer-server.
 * Return value:
 *      0   -> on success.
 *      -1  -> on some error.
 */
static inline int __send_all_fd (int sk, int fd, size_t size) {

    ssize_t ret = 0;
    size_t left = size;

    // Send all entire file.
    while (left > 0) {
        ret = sendfile (sk, fd, NULL, left);
        if (ret < 0) {
            pr_perror("Can't send file to the xfer-server (left: %ld)\n", left);
            return -1;
        }
        total_sent_bytes += ret;
        left = left - ret;
    }
	return 0;

}

/**
 * Shiv:
 * Function to send metadata about the dump file to the xfer-server.
 * Return value:
 *      0   -> to indicate success.
 *      -1  -> to indicate some error.
 */
static inline int send_metadata_xfer_server (int sk, struct xfer_metadata *meta) {

    long int ret = -1;
    ret = __send_all_buf (sk, meta, sizeof(*meta), 0);
    if (ret < 0) {
        pr_perror("Can't send metadata (%d) to the xfer-server", meta->type);
        return -1;
    }
	return 0;

}

/**
 * Shiv:
 * Function to send metadata and data (buf) to the xfer-server.
 * Return value:
 *      0   -> to indicate success.
 *      -1  -> to indicate some error.
 */
int send_to_xfer_server_buf (struct xfer_metadata *xfer_meta, const void *buf) {

    long int ret = -1;

    // Send entire metadata first.
    ret = send_metadata_xfer_server (xfer_server_sk, xfer_meta);
    if (ret < 0)
        return -1;
    // Now send entire data.
    ret = __send_all_buf (xfer_server_sk, buf, xfer_meta->size, 0);
    if (ret < 0) {
        pr_perror("Can't send dumped data (%d) to the xfer-server\n"
                , xfer_meta->type);
        return -1;
    }

    return 0;

}

/**
 * Shiv:
 * Function to send metadata and file (@fd) to the xfer-server.
 * Return value:
 *      0   -> to indicate success.
 *      -1  -> to indicate some error.
 */
int send_to_xfer_server_fd (struct xfer_metadata *xfer_meta, int fd) {

    long int ret = -1;

    // Send entire metadata first.
    ret = send_metadata_xfer_server (xfer_server_sk, xfer_meta);
    if (ret < 0)
        return -1;
    // Now send complete file.
    ret = __send_all_fd (xfer_server_sk, fd, (size_t)xfer_meta->size);
    if (ret < 0) {
        pr_perror("Can't send dumped file (%d) to the xfer-server with size %d\n"
                , xfer_meta->type, xfer_meta->size);
        return -1;
    }

    return 0;

}

/**
 * Shiv:
 * Function to send last page-iov command (PS_IOV_FLUSH) to xfer-server to
 * indicate completion of pages and pagemap transfer.
 * Return value:
 *      0   -> to indicate success.
 *      -1  -> to indicate some error.
 */
int send_last_page_iov_cmd_xfer () {

    struct page_server_iov pi = {};
    int ret = -1;
    int32_t status = -1;

    if (!(opts.use_xfer_server || opts.use_page_server))
        return 0;

    pi.cmd = PS_IOV_FLUSH_N_CLOSE;
    if (send_psi(xfer_server_sk, &pi))
        goto out;

    tcp_nodelay(xfer_server_sk, true);
    pr_debug ("Completion command for pages transfer is sent to xfer-server\n");

    if (__recv(xfer_server_sk, &status, sizeof(status), MSG_WAITALL) != sizeof(status)) {
        pr_perror("The xfer server doesn't answer");
        goto out;
    }

    ret = 0;

out:
    return ret ?: status;

}

/**
 * Shiv:
 * Function to indicate xfer-server that page-transfer is going to start.
 * Return value:
 *      0   -> on success.
 *      -1  -> on some error.
 */
int init_page_transfer_xfer_server (void) {

    struct xfer_metadata xfer_meta;

    // Return immediately, if xfer-server is not there to receive.
    if (!opts.use_xfer_server)
        return 0;

    xfer_meta.type = CR_FD_XF_REQ_PAGEMAP_AND_PAGES;
    xfer_meta.size = 0;
    if (send_metadata_xfer_server (xfer_server_sk, &xfer_meta) < 0) {
        pr_perror ("Unable to initiate page transfer using xfer-server");
        return -1;
    }
    return 0;

}

/**
 * Shiv:
 * Function to receive one dump file.
 * Return value:
 *      0   -> to indicate success.
 *      -1  -> to indicate some error.
 */
static inline int xfer_receive_one_dump (int sk, int ftype, void *buf
        , u32 sz, int fl, char *img_name) {

    long int ret = 0;
    long int left = sz;

    // Receive entire data.
    while (left > 0) {
        //ret = __recv (sk, (buf + ret), left, fl);
        ret = __recv (sk, buf, left, fl);
        if (ret < 0) {
            pr_perror ("Error while receiving dump file (%d) with"
                    " size %u (got %ld)\n", ftype, sz, ret);
            return -1;
        }
        buf = buf + ret;
        left = left - ret;
    }

    // Return success.
    if (img_name)
        pr_debug ("Dump file (%s) is received successfully\n", img_name);
    else
        pr_debug ("Dump file (%d) is received successfully\n", ftype);

    return 0;

}

/* page-server xfer */
static int write_pages_to_server (struct page_xfer *xfer, int p, unsigned long len) {

	ssize_t ret, left = len;

	if (opts.tls) {
		pr_debug("Sending %lu bytes / %lu pages\n", len, len / PAGE_SIZE);

		if (tls_send_data_from_fd(p, len))
			return -1;
	} else {
		pr_debug("Splicing %lu bytes / %lu pages into socket\n", len, len / PAGE_SIZE);

		while (left > 0) {
			ret = splice(p, NULL, xfer->sk, NULL, left, SPLICE_F_MOVE);
			if (ret < 0) {
				pr_perror("Can't write pages to socket");
				return -1;
			}

			pr_debug("\tSpliced: %lu bytes sent\n", (unsigned long)ret);
			left -= ret;
            total_sent_bytes += ret;
		}
	}

	return 0;

}

static int write_pagemap_to_server(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	struct page_server_iov pi = {
		.cmd = encode_ps_cmd(PS_IOV_ADD_F, flags),
		.nr_pages = iov->iov_len / PAGE_SIZE,
		.vaddr = encode_pointer(iov->iov_base),
		.dst_id = xfer->dst_id,
        .virt_pid = xfer->virt_pid,
	};

	return send_psi(xfer->sk, &pi);
}

static void close_server_xfer(struct page_xfer *xfer)
{
	xfer->sk = -1;
}

static int open_page_server_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	char has_parent;
	struct page_server_iov pi = {
		.cmd = PS_IOV_OPEN2,
	};

	xfer->sk = page_server_sk;
	xfer->write_pagemap = write_pagemap_to_server;
	xfer->write_pages = write_pages_to_server;
	xfer->close = close_server_xfer;
	xfer->dst_id = encode_pm(fd_type, img_id);
	xfer->parent = NULL;

	pi.dst_id = xfer->dst_id;
	if (send_psi(xfer->sk, &pi)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	/* Push the command NOW */
	tcp_nodelay(xfer->sk, true);

	if (__recv(xfer->sk, &has_parent, 1, MSG_WAITALL) != 1) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	if (has_parent)
		xfer->parent = (void *)1; /* This is required for generate_iovs() */

	return 0;
}

/* local xfer */
static int write_pages_loc(struct page_xfer *xfer, int p, unsigned long len)
{
	ssize_t ret;
	ssize_t curr = 0;

	while (1) {
		ret = splice(p, NULL, img_raw_fd(xfer->pi), NULL, len - curr, SPLICE_F_MOVE);
		if (ret == -1) {
			pr_perror("Unable to spice data");
			return -1;
		}
		if (ret == 0) {
			pr_err("A pipe was closed unexpectedly\n");
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	return 0;
}

static int check_pagehole_in_parent(struct page_read *p, struct iovec *iov)
{
	int ret;
	unsigned long off, end;

	/*
	 * Try to find pagemap entry in parent, from which
	 * the data will be read on restore.
	 *
	 * This is the optimized version of the page-by-page
	 * read_pagemap_page routine.
	 */

	pr_debug("Checking %p/%zu hole\n", iov->iov_base, iov->iov_len);
	off = (unsigned long)iov->iov_base;
	end = off + iov->iov_len;
	while (1) {
		unsigned long pend;

		ret = p->seek_pagemap(p, off);
		if (ret <= 0 || !p->pe) {
			pr_err("Missing %lx in parent pagemap\n", off);
			return -1;
		}

		pr_debug("\tFound %" PRIx64 "/%lu\n", p->pe->vaddr, pagemap_len(p->pe));

		/*
		 * The pagemap entry in parent may happen to be
		 * shorter, than the hole we write. In this case
		 * we should go ahead and check the remainder.
		 */

		pend = p->pe->vaddr + pagemap_len(p->pe);
		if (end <= pend)
			return 0;

		pr_debug("\t\tcontinue on %lx\n", pend);
		off = pend;
	}
}

static int write_pagemap_loc(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	int ret;
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	pe.vaddr = encode_pointer(iov->iov_base);
	pe.nr_pages = iov->iov_len / PAGE_SIZE;
	pe.has_flags = true;
	pe.flags = flags;

	if (flags & PE_PRESENT) {
		if (opts.auto_dedup && xfer->parent != NULL) {
			ret = dedup_one_iovec(xfer->parent, pe.vaddr, pagemap_len(&pe));
			if (ret == -1) {
				pr_perror("Auto-deduplication failed");
				return ret;
			}
		}
	} else if (flags & PE_PARENT) {
		if (xfer->parent != NULL) {
			ret = check_pagehole_in_parent(xfer->parent, iov);
			if (ret) {
				pr_err("Hole %p/%zu not found in parent\n", iov->iov_base, iov->iov_len);
				return -1;
			}
		}
	}

	if (pb_write_one(xfer->pmi, &pe, PB_PAGEMAP) < 0)
		return -1;

	return 0;
}

static void close_page_xfer(struct page_xfer *xfer)
{
	if (xfer->parent != NULL) {
		xfer->parent->close(xfer->parent);
		xfree(xfer->parent);
		xfer->parent = NULL;
	}
	close_image(xfer->pi);
	close_image(xfer->pmi);
}

static int open_page_local_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	u32 pages_id;

	xfer->pmi = open_image(fd_type, O_DUMP, img_id);
	if (!xfer->pmi)
		return -1;

	xfer->pi = open_pages_image(O_DUMP, xfer->pmi, &pages_id);
	if (!xfer->pi)
		goto err_pmi;

	/*
	 * Open page-read for parent images (if it exists). It will
	 * be used for two things:
	 * 1) when writing a page, those from parent will be dedup-ed
	 * 2) when writing a hole, the respective place would be checked
	 *    to exist in parent (either pagemap or hole)
	 */
	xfer->parent = NULL;
	if (fd_type == CR_FD_PAGEMAP || fd_type == CR_FD_SHMEM_PAGEMAP) {
		int ret;
		int pfd;
		int pr_flags = (fd_type == CR_FD_PAGEMAP) ? PR_TASK : PR_SHMEM;

		/* Image streaming lacks support for incremental images */
		if (opts.stream)
			goto out;

		if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
			goto err_pi;
		if (pfd < 0)
			goto out;

		xfer->parent = xmalloc(sizeof(*xfer->parent));
		if (!xfer->parent) {
			close(pfd);
			goto err_pi;
		}

        xfer->parent->is_pagemaps_cached = true;
		ret = open_page_read_at(pfd, img_id, xfer->parent, pr_flags);
		if (ret <= 0) {
			pr_perror("No parent image found, though parent directory is set");
			xfree(xfer->parent);
			xfer->parent = NULL;
			close(pfd);
			goto out;
		}
		close(pfd);
	}

out:
	xfer->write_pagemap = write_pagemap_loc;
	xfer->write_pages = write_pages_loc;
	xfer->close = close_page_xfer;
	return 0;

err_pi:
	close_image(xfer->pi);
err_pmi:
	close_image(xfer->pmi);
	return -1;
}

int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	xfer->offset = 0;
	xfer->transfer_lazy = true;
    xfer->virt_pid = (int) img_id;

	if (opts.use_page_server)
		return open_page_server_xfer(xfer, fd_type, img_id);
	else
		return open_page_local_xfer(xfer, fd_type, img_id);
}

static int page_xfer_dump_hole(struct page_xfer *xfer, struct iovec *hole, u32 flags)
{
	BUG_ON(hole->iov_base < (void *)xfer->offset);
	hole->iov_base -= xfer->offset;
	pr_debug("\th %p [%u]\n", hole->iov_base, (unsigned int)(hole->iov_len / PAGE_SIZE));

	if (xfer->write_pagemap(xfer, hole, flags))
		return -1;

	return 0;
}

static int get_hole_flags(struct page_pipe *pp, int n)
{
	unsigned int hole_flags = pp->hole_flags[n];

	if (hole_flags == PP_HOLE_PARENT)
		return PE_PARENT;
	else
		BUG();

	return -1;
}

static int dump_holes(struct page_xfer *xfer, struct page_pipe *pp, unsigned int *cur_hole, void *limit)
{
	int ret;

	for (; *cur_hole < pp->free_hole; (*cur_hole)++) {
		struct iovec hole = pp->holes[*cur_hole];
		u32 hole_flags;

		if (limit && hole.iov_base >= limit)
			break;

		hole_flags = get_hole_flags(pp, *cur_hole);
		ret = page_xfer_dump_hole(xfer, &hole, hole_flags);
		if (ret)
			return ret;
	}

	return 0;
}

static inline u32 ppb_xfer_flags(struct page_xfer *xfer, struct page_pipe_buf *ppb)
{
	if (ppb->flags & PPB_LAZY)
		/*
		 * Pages that can be lazily restored are always marked as such.
		 * In the case we actually transfer them into image mark them
		 * as present as well.
		 */
		return (xfer->transfer_lazy ? PE_PRESENT : 0) | PE_LAZY;
	else
		return PE_PRESENT;
}

/*
 * Optimized pre-dump algorithm
 * ==============================
 *
 * Note: Please refer man(2) page of process_vm_readv syscall.
 *
 * The following discussion covers the possibly faulty-iov
 * locations in an iovec, which hinders process_vm_readv from
 * dumping the entire iovec in a single invocation.
 *
 * Memory layout of target process:
 *
 * Pages: A        B        C
 *	  +--------+--------+--------+--------+--------+--------+
 *	  |||||||||||||||||||||||||||||||||||||||||||||||||||||||
 *	  +--------+--------+--------+--------+--------+--------+
 *
 * Single "iov" representation: {starting_address, length_in_bytes}
 * An iovec is array of iov-s.
 *
 * NOTE: For easy representation and discussion purpose, we carry
 *	 out further discussion at "page granularity".
 *	 length_in_bytes will represent page count in iov instead
 *	 of byte count. Same assumption applies for the syscall's
 *	 return value. Instead of returning the number of bytes
 *	 read, it returns a page count.
 *
 * For above memory mapping, generated iovec: {A,1}{B,1}{C,4}
 *
 * This iovec remains unmodified once generated. At the same
 * time some of memory regions listed in iovec may get modified
 * (unmap/change protection) by the target process while syscall
 * is trying to dump iovec regions.
 *
 * Case 1:
 *	A is unmapped, {A,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |        ||||||||||||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^        ^
 *      |        |
 *      start    |
 *      (1)      |
 *               start
 *               (2)
 *
 *	process_vm_readv will return -1. Increment start pointer(2),
 *	syscall will process {B,1}{C,4} in one go and copy 5 pages
 *	to userbuf from iov-B and iov-C.
 *
 * Case 2:
 *	B is unmapped, {B,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |||||||||         |||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                 ^
 *      |                 |
 *      start             |
 *      (1)               |
 *                        start
 *                        (2)
 *
 *	process_vm_readv will return 1, i.e. page A copied to
 *	userbuf successfully and syscall stopped, since B got
 *	unmapped.
 *
 *	Increment the start pointer to C(2) and invoke syscall.
 *	Userbuf contains 5 pages overall from iov-A and iov-C.
 *
 * Case 3:
 *	This case deals with partial unmapping of iov representing
 *	more than one pagesize region.
 *
 *	Syscall can't process such faulty iov as whole. So we
 *	process such regions part-by-part and form new sub-iovs
 *	in aux_iov from successfully processed pages.
 *
 *
 *	Part 3.1:
 *		First page of C is unmapped
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||         ||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                          ^
 *      |                          |
 *      start                      |
 *      (1)                        |
 *                                 dummy
 *                                 (2)
 *
 *	process_vm_readv will return 2, i.e. pages A and B copied.
 *	We identify length of iov-C is more than 1 page, that is
 *	where this case differs from Case 2.
 *
 *	dummy-iov is introduced(2) as: {C+1,3}. dummy-iov can be
 *	directly placed at next page to failing page. This will copy
 *	remaining 3 pages from iov-C to userbuf. Finally create
 *	modified iov entry in aux_iov. Complete aux_iov look like:
 *
 *	aux_iov: {A,1}{B,1}{C+1,3}*
 *
 *
 *	Part 3.2:
 *		In between page of C is unmapped, let's say third
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||||||||||||||||||||         ||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                                            ^
 *      |                 |-----------------|        |
 *      start              partial_read_bytes        |
 *      (1)                                          |
 *                                                   dummy
 *                                                   (2)
 *
 *	process_vm_readv will return 4, i.e. pages A and B copied
 *	completely and first two pages of C are also copied.
 *
 *	Since, iov-C is not processed completely, we need to find
 *	"partial_read_byte" count to place out dummy-iov for
 *	remainig processing of iov-C. This function is performed by
 *	analyze_iov function.
 *
 *	dummy-iov will be(2): {C+3,1}. dummy-iov will be placed
 *	next to first failing address to process remaining iov-C.
 *	New entries in aux_iov will look like:
 *
 *	aux_iov: {A,1}{B,1}{C,2}*{C+3,1}*
 */

unsigned long handle_faulty_iov(int pid, struct iovec *riov, unsigned long faulty_index, struct iovec *bufvec,
				struct iovec *aux_iov, unsigned long *aux_len, unsigned long partial_read_bytes)
{
	struct iovec dummy;
	ssize_t bytes_read;
	unsigned long offset = 0;
	unsigned long final_read_cnt = 0;

	/* Handling Case 2*/
	if (riov[faulty_index].iov_len == PAGE_SIZE) {
		cnt_sub(CNT_PAGES_WRITTEN, 1);
		return 0;
	}

	/* Handling Case 3-Part 3.2*/
	offset = (partial_read_bytes) ? partial_read_bytes : PAGE_SIZE;

	dummy.iov_base = riov[faulty_index].iov_base + offset;
	dummy.iov_len = riov[faulty_index].iov_len - offset;

	if (!partial_read_bytes)
		cnt_sub(CNT_PAGES_WRITTEN, 1);

	while (dummy.iov_len) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &dummy, 1, 0);

		if (bytes_read == -1) {
			/* Handling faulty page read in faulty iov */
			cnt_sub(CNT_PAGES_WRITTEN, 1);
			dummy.iov_base += PAGE_SIZE;
			dummy.iov_len -= PAGE_SIZE;
			continue;
		}

		/* If aux-iov can merge and expand or new entry required */
		if (aux_iov[(*aux_len) - 1].iov_base + aux_iov[(*aux_len) - 1].iov_len == dummy.iov_base)
			aux_iov[(*aux_len) - 1].iov_len += bytes_read;
		else {
			aux_iov[*aux_len].iov_base = dummy.iov_base;
			aux_iov[*aux_len].iov_len = bytes_read;
			(*aux_len) += 1;
		}

		dummy.iov_base += bytes_read;
		dummy.iov_len -= bytes_read;
		bufvec->iov_base += bytes_read;
		bufvec->iov_len -= bytes_read;
		final_read_cnt += bytes_read;
	}

	return final_read_cnt;
}

/*
 * This function will position start pointer to the latest
 * successfully read iov in iovec. In case of partial read it
 * returns partial_read_bytes, otherwise 0.
 */
static unsigned long analyze_iov(ssize_t bytes_read, struct iovec *riov, unsigned long *index, struct iovec *aux_iov,
				 unsigned long *aux_len)
{
	ssize_t processed_bytes = 0;
	unsigned long partial_read_bytes = 0;

	/* correlating iovs with read bytes */
	while (processed_bytes < bytes_read) {
		processed_bytes += riov[*index].iov_len;
		aux_iov[*aux_len].iov_base = riov[*index].iov_base;
		aux_iov[*aux_len].iov_len = riov[*index].iov_len;

		(*aux_len) += 1;
		(*index) += 1;
	}

	/* handling partially processed faulty iov*/
	if (processed_bytes - bytes_read) {
		(*index) -= 1;

		partial_read_bytes = riov[*index].iov_len - (processed_bytes - bytes_read);
		aux_iov[*aux_len - 1].iov_len = partial_read_bytes;
	}

	return partial_read_bytes;
}

/*
 * This function iterates over complete ppb->iov entries and pass
 * them to process_vm_readv syscall.
 *
 * Since process_vm_readv returns count of successfully read bytes.
 * It does not point to iovec entry associated to last successful
 * byte read. The correlation between bytes read and corresponding
 * iovec is setup through analyze_iov function.
 *
 * If all iovecs are not processed in one go, it means there exists
 * some faulty iov entry(memory mapping modified after it was grabbed)
 * in iovec. process_vm_readv syscall stops at such faulty iov and
 * skip processing further any entry in iovec. This is handled by
 * handle_faulty_iov function.
 */
static long fill_userbuf(int pid, struct page_pipe_buf *ppb, struct iovec *bufvec, struct iovec *aux_iov,
			 unsigned long *aux_len)
{
	struct iovec *riov = ppb->iov;
	ssize_t bytes_read;
	unsigned long total_read = 0;
	unsigned long start = 0;
	unsigned long partial_read_bytes = 0;

	while (start < ppb->nr_segs) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &riov[start], ppb->nr_segs - start, 0);

		if (bytes_read == -1) {
			/* Handling Case 1*/
			if (riov[start].iov_len == PAGE_SIZE) {
				cnt_sub(CNT_PAGES_WRITTEN, 1);
				start += 1;
				continue;
			} else if (errno == ESRCH) {
				pr_debug("Target process PID:%d not found\n", pid);
				return ESRCH;
			}
		}

		partial_read_bytes = 0;

		if (bytes_read > 0) {
			partial_read_bytes = analyze_iov(bytes_read, riov, &start, aux_iov, aux_len);
			bufvec->iov_base += bytes_read;
			bufvec->iov_len -= bytes_read;
			total_read += bytes_read;
		}

		/*
		 * If all iovs not processed in one go,
		 * it means some iov in between has failed.
		 */
		if (start < ppb->nr_segs)
			total_read += handle_faulty_iov(pid, riov, start, bufvec, aux_iov, aux_len, partial_read_bytes);

		start += 1;
	}

	return total_read;
}

/*
 * This function is similar to page_xfer_dump_pages, instead it uses
 * auxiliary_iov array for pagemap generation.
 *
 * The entries of ppb->iov may mismatch with actual process mappings
 * present at time of pre-dump. Such entries need to be adjusted as per
 * the pages read by process_vm_readv syscall. These adjusted entries
 * along with unmodified entries are present in aux_iov array.
 */

int page_xfer_predump_pages(int pid, struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0, i;
	unsigned long ret, bytes_read;
	struct iovec bufvec;

	struct iovec aux_iov[PIPE_MAX_SIZE];
	unsigned long aux_len;

	char *userbuf = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (userbuf == MAP_FAILED) {
		pr_perror("Unable to mmap a buffer");
		return -1;
	}

	list_for_each_entry(ppb, &pp->bufs, l) {
		timing_start(TIME_MEMDUMP);

		aux_len = 0;
		bufvec.iov_len = BUFFER_SIZE;
		bufvec.iov_base = userbuf;

		bytes_read = fill_userbuf(pid, ppb, &bufvec, aux_iov, &aux_len);

		if (bytes_read == ESRCH) {
			munmap(userbuf, BUFFER_SIZE);
			return -1;
		}

		bufvec.iov_base = userbuf;
		bufvec.iov_len = bytes_read;
		ret = vmsplice(ppb->p[1], &bufvec, 1, SPLICE_F_NONBLOCK);

		if (ret == -1 || ret != bytes_read) {
			pr_err("vmsplice: Failed to splice user buffer to pipe %ld\n", ret);
			munmap(userbuf, BUFFER_SIZE);
			return -1;
		}

		timing_stop(TIME_MEMDUMP);
		timing_start(TIME_MEMWRITE);

		/* generating pagemap */
		for (i = 0; i < aux_len; i++) {
			struct iovec iov = aux_iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret) {
				munmap(userbuf, BUFFER_SIZE);
				return ret;
			}

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\t p %p [%u]\n", iov.iov_base, (unsigned int)(iov.iov_len / PAGE_SIZE));

			flags = ppb_xfer_flags(xfer, ppb);

			if (xfer->write_pagemap(xfer, &iov, flags)) {
				munmap(userbuf, BUFFER_SIZE);
				return -1;
			}

			if (xfer->write_pages(xfer, ppb->p[0], iov.iov_len)) {
				munmap(userbuf, BUFFER_SIZE);
				return -1;
			}
		}

		timing_stop(TIME_MEMWRITE);
	}

	munmap(userbuf, BUFFER_SIZE);
	timing_start(TIME_MEMWRITE);

	return dump_holes(xfer, pp, &cur_hole, NULL);
}

int page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0;
	int ret;

	pr_debug("Transferring pages:\n");

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("\tbuf %d/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				return ret;

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\tp %p [%u]\n", iov.iov_base, (unsigned int)(iov.iov_len / PAGE_SIZE));

			flags = ppb_xfer_flags(xfer, ppb);

			if (xfer->write_pagemap(xfer, &iov, flags))
				return -1;
			if ((flags & PE_PRESENT) && xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				return -1;
		}
	}

	return dump_holes(xfer, pp, &cur_hole, NULL);
}

/*
 * Return:
 *	 1 - if a parent image exists
 *	 0 - if a parent image doesn't exist
 *	-1 - in error cases
 */
int check_parent_local_xfer(int fd_type, unsigned long img_id)
{
	char path[PATH_MAX];
	struct stat st;
	int ret, pfd;

	/* Image streaming lacks support for incremental images */
	if (opts.stream)
		return 0;

	if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
		return -1;
	if (pfd < 0)
		return 0;

	snprintf(path, sizeof(path), imgset_template[fd_type].fmt, img_id);
	ret = fstatat(pfd, path, &st, 0);
	if (ret == -1 && errno != ENOENT) {
		pr_perror("Unable to stat %s", path);
		close(pfd);
		return -1;
	}

	close(pfd);
	return (ret == 0);
}

/* page server */
static int page_server_check_parent(int sk, struct page_server_iov *pi)
{
	int type, ret;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	ret = check_parent_local_xfer(type, id);
	if (ret < 0)
		return -1;

	if (__send(sk, &ret, sizeof(ret), 0) != sizeof(ret)) {
		pr_perror("Unable to send response");
		return -1;
	}
	tcp_nodelay (sk, true);

	return 0;
}

static int check_parent_server_xfer(int fd_type, unsigned long img_id)
{
	struct page_server_iov pi = {};
	int has_parent;
    struct xfer_metadata meta;

    // Shiv:
    // Check for xfer-server option.
    if (opts.use_xfer_server) {
        
        // Prepare metadata and send it to xfer-server.
        meta.type = CR_FD_XF_REQ_IOV_PARENT;
        meta.size = 0;
        meta.dst_id = encode_pm(fd_type, img_id);
        if (send_metadata_xfer_server (xfer_server_sk, &meta) < 0)
            return -1;

    } else {

        pi.cmd = PS_IOV_PARENT;
        pi.dst_id = encode_pm(fd_type, img_id);

        if (send_psi(page_server_sk, &pi))
            return -1;

    }

	tcp_nodelay(page_server_sk, true);

	if (__recv(page_server_sk, &has_parent, sizeof(int), MSG_WAITALL) != sizeof(int)) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	return has_parent;
}

int check_parent_page_xfer(int fd_type, unsigned long img_id)
{
	if (opts.use_page_server)
		return check_parent_server_xfer(fd_type, img_id);
	else
		return check_parent_local_xfer(fd_type, img_id);
}

struct page_xfer_job {
	u64 dst_id;
	int p[2];
	unsigned pipe_size;
	struct page_xfer loc_xfer;
};

static struct page_xfer_job cxfer = {
	.dst_id = ~0,
};

static struct pipe_read_dest pipe_read_dest = {
	.sink_fd = -1,
};

static void page_server_close (void) {

	if (cxfer.dst_id != ~0) {
		cxfer.loc_xfer.close(&cxfer.loc_xfer);
        cxfer.dst_id = ~0;
    }

	if (pipe_read_dest.sink_fd != -1) {
		close(pipe_read_dest.sink_fd);
		close(pipe_read_dest.p[0]);
		close(pipe_read_dest.p[1]);
        pipe_read_dest.sink_fd = -1;
	}

}

static inline int __signal_prestore_data (int length) {

    int fd, ret = 0;
    int done = 0;

    // XXX: Shiv
    // Restore process may not have created the fifo yet due to some lag/ speed.
    // Hence wait untill restore process creates the fifo.
    while (!done) {
        if (access(PRESTORE_PIPE_XFER_TO_CRIU_DATA, F_OK) == 0)
            done = 1;
        usleep (500);
    }

    fd = open (PRESTORE_PIPE_XFER_TO_CRIU_DATA, O_RDWR);
    if (fd < 0) {
        pr_perror ("Error: fifo data pipe open failed during signaling!!!\n");
        return 0;
    }
    if (write (fd, &length, sizeof(int)) != sizeof(int)) {
        pr_perror ("Error: Writing to data pipe failed during signaling!!!\n");
        ret = -1;
    }
    close (fd);
    return ret;

}

static int page_server_open(int sk, struct page_server_iov *pi)
{
	int type;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	pr_info("Opening %d/%lu\n", type, id);

	page_server_close();

	if (open_page_local_xfer(&cxfer.loc_xfer, type, id))
		return -1;

	cxfer.dst_id = pi->dst_id;

	if (sk >= 0) {
		char has_parent = !!cxfer.loc_xfer.parent;
		if (__send(sk, &has_parent, 1, 0) != 1) {
			pr_perror("Unable to send response");
			close_page_xfer(&cxfer.loc_xfer);
			return -1;
		}
		tcp_nodelay (sk, true);
	}

	return 0;
}

static int prep_loc_xfer(struct page_server_iov *pi)
{
	if (cxfer.dst_id != pi->dst_id) {
		pr_warn("Deprecated IO w/o open\n");
		return page_server_open(-1, pi);
	} else
		return 0;
}

static int page_server_add(int sk, struct page_server_iov *pi, u32 flags) {

	size_t len;
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	struct iovec iov;

	pr_debug("Adding %" PRIx64 "/%u\n", pi->vaddr, pi->nr_pages);

	if (prep_loc_xfer(pi))
		return -1;

	psi2iovec(pi, &iov);
	if (lxfer->write_pagemap(lxfer, &iov, flags))
		return -1;

	if (!(flags & PE_PRESENT)) {
		return 0;
	}

	len = iov.iov_len;
	while (len > 0) {
		ssize_t chunk;

		chunk = len;
		if (chunk > cxfer.pipe_size)
			chunk = cxfer.pipe_size;

		/*
		 * Splicing into a pipe may end up blocking if pipe is "full",
		 * and we need the SPLICE_F_NONBLOCK flag here. At the same time
		 * splicing from UNIX socket with this flag aborts splice with
		 * the EAGAIN if there's no data in it (TCP looks at the socket
		 * O_NONBLOCK flag _only_ and waits for data), so before doing
		 * the non-blocking splice we need to explicitly wait.
		 */

		if (sk_wait_data(sk) < 0) {
			pr_perror("Can't poll socket");
			return -1;
		}

		if (opts.tls) {
			if (tls_recv_data_to_fd(cxfer.p[1], chunk)) {
				pr_err("Can't read from socket\n");
				return -1;
			}
		} else {
			chunk = splice(sk, NULL, cxfer.p[1], NULL, chunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

			if (chunk < 0) {
				pr_perror("Can't read from socket");
				return -1;
			}
			if (chunk == 0) {
				pr_err("A socket was closed unexpectedly\n");
				return -1;
			}
		}

		if (lxfer->write_pages(lxfer, cxfer.p[0], chunk))
			return -1;

		len -= chunk;
	}

	return 0;

}

static int page_server_get_pages(int sk, struct page_server_iov *pi)
{
	struct pstree_item *item;
	struct page_pipe *pp;
	unsigned long len;
	int ret;

	item = pstree_item_by_virt(pi->dst_id);
	pp = dmpi(item)->mem_pp;

	ret = page_pipe_read(pp, &pipe_read_dest, pi->vaddr, &pi->nr_pages, PPB_LAZY);
	if (ret)
		return ret;

	/*
	 * The pi is reused for send_psi here, so .nr_pages, .vaddr and
	 * .dst_id all remain intact.
	 */

	if (pi->nr_pages == 0) {
		pr_debug("no iovs found, zero pages\n");
		return -1;
	}

	pi->cmd = encode_ps_cmd(PS_IOV_ADD_F, PE_PRESENT);
	if (send_psi(sk, pi))
		return -1;

	len = pi->nr_pages * PAGE_SIZE;

	if (opts.tls) {
		if (tls_send_data_from_fd(pipe_read_dest.p[0], len))
			return -1;
	} else {
		ret = splice(pipe_read_dest.p[0], NULL, sk, NULL, len, SPLICE_F_MOVE);
		if (ret != len)
			return -1;
	}

	tcp_nodelay(sk, true);

	return 0;
}

static int page_server_serve(int sk)
{
	int ret = -1;
	bool flushed = false;
	bool receiving_pages = !opts.lazy_pages;

	if (receiving_pages) {
		/*
		 * This socket only accepts data except one thing -- it
		 * writes back the has_parent bit from time to time, so
		 * make it NODELAY all the time.
		 */
		tcp_nodelay(sk, true);

		if (pipe(cxfer.p)) {
			pr_perror("Can't make pipe for xfer");
			close(sk);
			return -1;
		}

		cxfer.pipe_size = fcntl(cxfer.p[0], F_GETPIPE_SZ, 0);
		pr_debug("Created xfer pipe size %u\n", cxfer.pipe_size);
	} else {
		pipe_read_dest_init(&pipe_read_dest);
		tcp_cork(sk, true);
	}

	while (1) {
		struct page_server_iov pi;
		u32 cmd;

		ret = __recv(sk, &pi, sizeof(pi), MSG_WAITALL);
		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			ret = -1;
			break;
		}

		flushed = false;
		cmd = decode_ps_cmd(pi.cmd);

		switch (cmd) {
		case PS_IOV_OPEN:
			ret = page_server_open(-1, &pi);
			break;
		case PS_IOV_OPEN2:
			ret = page_server_open(sk, &pi);
			break;
		case PS_IOV_PARENT:
			ret = page_server_check_parent(sk, &pi);
			break;
		case PS_IOV_ADD_F:
		case PS_IOV_ADD:
		case PS_IOV_HOLE: {
			u32 flags;

			if (likely(cmd == PS_IOV_ADD_F))
				flags = decode_ps_flags(pi.cmd);
			else if (cmd == PS_IOV_ADD)
				flags = PE_PRESENT;
			else /* PS_IOV_HOLE */
				flags = PE_PARENT;


			ret = page_server_add(sk, &pi, flags);
			break;
		}
		case PS_IOV_FLUSH:
		case PS_IOV_FLUSH_N_CLOSE: {
			int32_t status = 0;

			ret = 0;

			/*
			 * An answer must be sent back to inform another side,
			 * that all data were received
			 */
			if (__send(sk, &status, sizeof(status), 0) != sizeof(status)) {
				pr_perror("Can't send the final package");
				ret = -1;
			}

			flushed = true;
			break;
		}
		case PS_IOV_GET:
			ret = page_server_get_pages(sk, &pi);
			break;
		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ret = -1;
			break;
		}

		if (ret || (pi.cmd == PS_IOV_FLUSH_N_CLOSE))
			break;
	}

	if (receiving_pages && !ret && !flushed) {
		pr_err("The data were not flushed\n");
		ret = -1;
	}

	if (ret == 0 && opts.ps_socket == -1) {
		char c;

		/*
		 * Wait when a remote side closes the connection
		 * to avoid TIME_WAIT bucket
		 */
		if (read(sk, &c, sizeof(c)) != 0) {
			pr_perror("Unexpected data");
			ret = -1;
		}
	}

	tls_terminate_session();
	page_server_close();

	pr_info("Session over\n");

	close(sk);
	return ret;
}


// Function to create and set options related to images-dir and prev-images-dir.
int setup_images_dir (int iteration, bool is_restore, bool check_parent) {
    
    int ret = -1;
    int fd;

    // XXX:
    // Considering iteration value will be always less than 2 digits.
    char rel_img_path [8];
    char rel_parent_path [18];

    // Create image directory for this iteration, if not already created.
    // TODO:
    // 1.) Set IMG_ROOT_FD_OFF by calling open_image_root_dir from entrypoint
    //     of xfer-server. (done)
    // 2.) Implement open_image_dir_at similiar to open_image_dir but with
    //     provided fd parameter instead of dirname.
    // 3.) Set parent path to be used to 2nd step.
    // 4.) Undo whatever is done in 1st and 2nd at appropriate places.
    fd = get_service_fd (IMG_ROOT_FD_OFF);
    if (fd < 0)
        goto err;

    sprintf (rel_img_path, "%d", iteration);

    // Skip the creation of directory if it is restore.
    if (is_restore)
        goto skip_dir_creation;

    ret = mkdirat (fd, rel_img_path, 0766);
    if (ret && (errno != EEXIST)) {
        pr_perror ("Can not create directory for this iteration");
        goto err;
    }

skip_dir_creation:
    // Set parent image option (img_parent) of criu options, i.e., opts, if
    // iteration is greater than 1.
    if (iteration == 1)
        goto open_dir;

    sprintf (rel_parent_path, "../%d/", (iteration - 1));
    SET_CHAR_OPTS(img_parent, rel_parent_path);

open_dir:
    ret = open_image_dir_at (fd, rel_img_path, check_parent);
    if (ret < 0) {
        pr_perror("Couldn't open relative image dir %s\n", opts.imgs_dir);
        goto err;
    }

    return 0;

err:
    return ret;

} 

/**
 * TODO: Shiv
 *
 * Currently executing only following command to start the parallel restore via runc bin.
 *      "runc restore --bundle <abs_path> --image-path <abs_path>
 *              --work-path <abs_path> --iterations <number> --rp <number>
 *              --use-mmap --file-locks --shell-job
 *              --tcp-established --auto-dedup <container-name>
 *
 */
static inline int __start_prestore_direct (void) {

    char **prestore_cmd;
    int max_args = 18;
    int i, pid;
    char custom_container_name[PATH_MAX] = "redis-restore";

    // Allocate command buffer.
    prestore_cmd = (char **) xzalloc ((max_args + 1) * (sizeof (char*)));
    for (i = 0; i < max_args; i++)
        prestore_cmd[i] = (char *) xzalloc (PATH_MAX * sizeof (char));

    // Prepare the command array to pass in execv.
    i = 0;
    strcpy(prestore_cmd[i++], "runc");
    strcpy(prestore_cmd[i++], "restore");
    strcpy(prestore_cmd[i++], "--bundle");
    strcpy(prestore_cmd[i++], opts.bundle);
    strcpy(prestore_cmd[i++], "--image-path");
    strcpy(prestore_cmd[i], opts.imgs_dir);
    if (opts.imgs_dir[strlen(opts.imgs_dir) - 1] != '/')
        strcat(prestore_cmd[i], "/");
    strcat(prestore_cmd[i++], "1");
    strcpy(prestore_cmd[i++], "--work-path");
    strcpy(prestore_cmd[i++], opts.work_dir);
    strcpy(prestore_cmd[i++], "--iterations");
    sprintf(prestore_cmd[i++], "%d", opts.iterations);
    strcpy(prestore_cmd[i++], "--rp");
    sprintf(prestore_cmd[i++], "%d", opts.rp);
    if (opts.use_mmap)
        strcpy(prestore_cmd[i++], "--use-mmap");
    if (opts.handle_file_locks)
        strcpy(prestore_cmd[i++], "--file-locks");
    if (opts.shell_job)
        strcpy(prestore_cmd[i++], "--shell-job");
    strcpy(prestore_cmd[i++], "--tcp-established");
    strcpy(prestore_cmd[i++], "--auto-dedup");
    strcpy(prestore_cmd[i++], custom_container_name);
    prestore_cmd[i] = NULL;

    // Now call execv in child.
    pid = fork ();
    if (pid == -1) {
        pr_perror ("Error: Can not fork!!!\n");
        return -1;
    } else if (pid == 0) {

        char container_log_file [PATH_MAX];
        int logfd = -1;

        // dup both stdout and stderr to some file in working path.
        strcpy (container_log_file, opts.work_dir);
        if (opts.work_dir[strlen(opts.work_dir) - 1] != '/')
            strcat (container_log_file, "/");
        strcat (container_log_file, "container.log");
        logfd = open (container_log_file, O_CREAT | O_TRUNC | O_WRONLY | O_APPEND, 0600);
        if (logfd < 0) {
            pr_perror ("Error: Can't create container log file %s\n", container_log_file);
            exit (-1);
        }
        if (dup2 (logfd, STDOUT_FILENO) == -1 || dup2 (logfd, STDERR_FILENO) == -1) {
            pr_perror("Error: Failed to redirect stdout and stderr to the container logfile");
            exit (-1);
        }
        close (logfd);

        // Close image directories for this process.
        close_image_dir ();
        close_image_root_dir ();

        // Now launch
        execv ("/usr/local/sbin/runc", prestore_cmd);
        pr_perror ("Error: execv failed!!!\n");
        exit (-1);

    }

    return 0;

}

/**
 * TODO: Shiv
 *
 * XXX: This does not consider --rp (restoration point) flag while launching
 *      the script.
 *
 * Currently executing only following command to start the parallel restore via script file.
 *      "runc restore --bundle <abs_path> --image-path <abs_path>
 *              --work-path <abs_path> --iterations <number>
 *              --tcp-established <container-name>
 *
 */
static inline int __start_prestore_script (void) {

    char **prestore_cmd;
    int max_args = 5;
    int i, pid;

    // Allocate command buffer.
    prestore_cmd = (char **) xzalloc ((max_args + 1) * (sizeof (char*)));
    for (i = 0; i < max_args; i++)
        prestore_cmd[i] = (char *) xzalloc (PATH_MAX * sizeof (char));

    // Prepare the command array to pass in execv.
    strcpy(prestore_cmd[0], "./");
    strcpy(prestore_cmd[0], opts.work_dir);
    if (opts.work_dir[strlen(opts.work_dir) - 1] != '/')
        strcat(prestore_cmd[0], "/");
    strcat(prestore_cmd[0], "container_restore_diskless_pcriu.sh");
    strcpy(prestore_cmd[1], opts.imgs_dir);
    if (opts.imgs_dir[strlen(opts.imgs_dir) - 1] != '/')
        strcat(prestore_cmd[1], "/");
    strcat(prestore_cmd[1], "1");
    strcpy(prestore_cmd[2], opts.bundle);
    sprintf(prestore_cmd[3], "%d", opts.iterations);
    strcpy(prestore_cmd[4], opts.container_name);
    prestore_cmd[max_args] = NULL;

    // Now call execv in child.
    pid = fork ();
    if (pid == -1) {
        pr_perror ("Error: Can not fork!!!\n");
        return -1;
    } else if (pid == 0) {

        char launch_log_file [PATH_MAX];
        int logfd = -1;

        // dup both stdout and stderr to some file in working path.
        strcpy (launch_log_file, opts.work_dir);
        if (opts.work_dir[strlen(opts.work_dir) - 1] != '/')
            strcat (launch_log_file, "/");
        strcat (launch_log_file, "launch_prestore.log");
        logfd = open (launch_log_file, O_CREAT | O_TRUNC | O_WRONLY | O_APPEND, 0600);
        if (logfd < 0) {
            pr_perror ("Error: Can't create container log file %s\n", launch_log_file);
            exit (-1);
        }
        if (dup2 (logfd, STDOUT_FILENO) == -1 || dup2 (logfd, STDERR_FILENO) == -1) {
            pr_perror("Error: Failed to redirect stdout and stderr to the container logfile");
            exit (-1);
        }
        close (logfd);

        // Close image directories for this process.
        close_image_dir ();
        close_image_root_dir ();

        // Now launch
        execv (prestore_cmd[0], prestore_cmd);
        pr_perror ("Error: execv failed!!!\n");
        exit (-1);

    }

    return 0;

}

/**
 * XXX: Shiv
 *
 * Here I am assuming that parallel restore's main task will create a named fifo
 * pipe in first iteration, so this function only open the named fifo pipe and
 * write pid to give go signal to the specific task (CRIU or child of CRIU)
 * which is waiting for it after completing the processing of previous iteration.
 * It writes 2 kind of values to the pipe:
 *      i)  0: To signal the completion of global info receiving.
 *      ii) pid: To signal the start of page transfer for a specific task.
 *
 * The creation and deletion of named fifo pipe is the responsibility of
 * parallel restore's main task.
 */
static inline int __signal_prestore (int virt_pid) {

    int fd, ret = 0;
    int done = 0;

    // XXX: Shiv
    // Restore process may not have created the fifo yet due to some lag/ speed.
    // Hence wait untill restore process creates the fifo.
    while (!done) {
        if (access(PRESTORE_PIPE_XFER_TO_CRIU_MSG, F_OK) == 0)
            done = 1;
        usleep (500);
    }

    fd = open (PRESTORE_PIPE_XFER_TO_CRIU_MSG, O_WRONLY);
    if (fd < 0) {
        pr_perror ("Error: fifo pipe open failed!!!\n");
        return -1;
    }
    if (write (fd, &virt_pid, sizeof(int)) != sizeof(int)) {
        pr_perror ("Error: Writing to pipe failed!!!\n");
        ret = -1;
    }
    close (fd);
    return ret;

}

// Shiv:
// Function to receive pages and pagemap dumps.
static inline int xfer_receive_pages_dumps (int sk) {

	int ret = -1;
	bool flushed = false;
    int prev_virt_pid = -1;
    int num_times = 0;

    // Receive pages and pagemap.
	while (1) {
		struct page_server_iov pi;
		u32 cmd;

		ret = __recv(sk, &pi, sizeof(pi), MSG_WAITALL);
		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			ret = -1;
			break;
		}

		flushed = false;
		cmd = decode_ps_cmd(pi.cmd);

		switch (cmd) {
		case PS_IOV_OPEN:
			ret = page_server_open(-1, &pi);
			break;
		case PS_IOV_OPEN2:
			ret = page_server_open(sk, &pi);
			break;
		case PS_IOV_PARENT:
			ret = page_server_check_parent(sk, &pi);
			break;
		case PS_IOV_ADD_F:
		case PS_IOV_ADD:
		case PS_IOV_HOLE: {
			u32 flags;

            // Signal parallel restore task if its already created in previous
            // iteration.
            if (prestore_started && (cmd == PS_IOV_ADD_F)) {
                if (prev_virt_pid != pi.virt_pid) {
                    prev_virt_pid = pi.virt_pid;
		    if (num_times < 2) {
			    num_times++;
		    }
                    if (__signal_prestore(pi.virt_pid)) {
                        ret = -1;
                        pr_perror ("Error while signaling parallel restore for "
                            "successive iteration!!!\n");
                        return -1;
                    }

		    // Append end marker in data pipe to indicate end of one process page transfer.
		    if (num_times > 1) {
			    num_times = 2;
			    if (__signal_prestore_data (-1)) {
				    ret = -1;
				    pr_perror ("Error while appending end marker for pid %d\n", prev_virt_pid);
				    break;
			    }
		    }
                }
            }

			if (likely(cmd == PS_IOV_ADD_F))
				flags = decode_ps_flags(pi.cmd);
			else if (cmd == PS_IOV_ADD)
				flags = PE_PRESENT;
			else /* PS_IOV_HOLE */
				flags = PE_PARENT;

			ret = page_server_add(sk, &pi, flags);
			break;
		}
		case PS_IOV_FLUSH:
		case PS_IOV_FLUSH_N_CLOSE: {
			int32_t status = 0;

			ret = 0;

			/*
			 * An answer must be sent back to inform another side,
			 * that all data were received
			 */
			if (__send(sk, &status, sizeof(status), 0) != sizeof(status)) {
				pr_perror("Can't send the final package");
				ret = -1;
			}
			tcp_nodelay (sk, true);

			flushed = true;
			break;
		}

		case PS_IOV_GET:
			ret = page_server_get_pages(sk, &pi);
			break;

		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ret = -1;
			break;
		}

		if (ret || (pi.cmd == PS_IOV_FLUSH_N_CLOSE))
			break;

	}

	if (!ret && !flushed) {
		pr_err("The data were not flushed\n");
		ret = -1;
	}


    // Append end marker in data pipe to indicate end of one process page transfer.
    if (prestore_started && !ret && __signal_prestore_data (-1)) {
	    ret = -1;
	    pr_perror ("Error while appending end marker for pid %d\n", prev_virt_pid);
    }

    // Return
    return ret;

}

/**
 * Shiv:
 * Function to write raw data (@buf) to file (@fd).
 * Return value:
 *      0   -> to indicate success.
 *      -1  -> to indicate some error.
 */
static inline int write_raw_data (int fd, char *fname, void *buf, u32 sz) {

    long int ret = 0;
    long int left = sz;

    // Receive entire data.
    while (left > 0) {
        ret = write (fd, buf, left);
        if (ret < 0) {
            pr_perror ("Error while writing raw data to local file (%s)"
                    " with left size: %ld\n", fname, left);
            return -1;
        }
	buf = buf + ret;
        left = left - ret;
    }

    // Return success.
    pr_debug ("Raw dump file (%s) is saved successfully\n", fname);
    return 0;

}

/**
 * Shiv:
 * Function to receive other dump (other than pages) files.
 * Return values:
 *      0   -> Indicating no error.
 *      -1  -> Indicating some error.
 *
 * XXX:
 * It may receive transfer request with same file type mutiple times like
 * in case of "CR_FD_FILES". So BE CAREFULL!!!
 * I have mentioned inside switch case which files are dumped multiple times
 * using tag "MULTIPLE"
 *
 */
static inline int xfer_receive_other_dumps (struct cr_img **img, int sk
        , void *buf, struct xfer_metadata *metadata) {

    int ret     = -1;
    u32 size    = metadata->size;
    int ftype   = metadata->type;

    // Receive the dump file
    if (xfer_receive_one_dump (sk, ftype, buf, size, MSG_WAITALL, metadata->img_name) < 0)
        return ret;
    
    // Open the image (if not opened in pervious request) and save the received
    // dump file locally.
    if (*img != NULL) {
        if (!strcmp((*img)->name, metadata->img_name)) {
            goto skip_img_open;
        } else {
            close_image(*img);
            *img = NULL;
        }
    }
    
    *img = open_image_at (-1, metadata->img_name, ftype, O_DUMP);
    if (!(*img))
        return ret;

skip_img_open:
    // Write data as raw if type is CR_FD_TMPFS_DEV (to create raw image file
    // tmpfs-dev-%u.tar.gz.img) else do structured protobuf write.
    //
    // Shiv: New image saving/ writing -> WORKED :)
    switch (metadata->save_method) {
        case PB_IMG_BUF:
            ret = pb_write_one_buf (*img, NULL, -1, buf, size);
            break;
        case CR_IMG_RAW:
            ret = write_raw_data (img_raw_fd(*img), metadata->img_name, buf, size);
	    xfree (buf);
            break;
        case CR_IMG_BUF:
            ret = write_img_buf (*img, buf, size);
	    xfree (buf);
            break;
        default:
            pr_perror ("BUG: Unexpected image saving method (type: %d)!!!!\n", ftype);
            BUG_ON(true);
    }

    return ret;

}

/**
 * Function to receive runc dump (descriptors.json file).
 * Return values:
 *      0   -> Indicating no error.
 *      -1  -> Indicating some error.
 *
 */
static inline int xfer_receive_runc_dump (int sk, struct xfer_metadata *metadata) {

    int ret     = -1;
    u32 size    = metadata->size;
    int ftype   = metadata->type;
    void *buf   = NULL;
    int dirfd   = -1;
    int fd      = -1;

    buf = xmalloc (size);
    if (!buf) {
        pr_perror ("Error while allocating buffer for runc dump!!!\n");
        return -1;
    }

    // Receive the dump file, i.e. descriptors.json
    if (xfer_receive_one_dump (sk, ftype, buf, size, MSG_WAITALL, metadata->img_name) < 0)
        return -1;

    dirfd = get_service_fd (IMG_FD_OFF);
    if (dirfd < 0)
        return -1;
    fd = openat (dirfd, metadata->img_name, O_DUMP, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return -1;

    // Now write to the file and save.
    ret = write_raw_data (fd, metadata->img_name, buf, size);
    close (fd);
    return ret;

}

/**
 * Shiv:
 *
 * Description:
 * Function to receive all dumps (pages, pstree, and others) from sender node
 * for each iterations and save those at receiver node. To receive and save
 * dump images in each iterations it also create directories before receiving
 * the dump images.
 *
 * Protocol:
 * First metadata about dump file is received and then actual dump file is
 * received.
 *
 * This function also act as a wrapper to receive pages and pagemap by calling
 * already implemented function to receive pages and pagemap.
 *
 */
static int xfer_server_serve (int sk, int iteration) {

    struct timeval t;
    int ret = -1;
    int done = 0;
    
    // This socket only accept data so make it NODELAY all the time.
    // Same as page_server_server comment for this.
    tcp_nodelay(sk, true);

    gettimeofday(&t, NULL);
    pr_debug ("xfer-server: %dth iteration started (timestamp: %ld.%ld).\n", iteration, t.tv_sec, t.tv_usec);

    // Create subdirectory in provided image directory, set imgs_dir
    // and img_parent options of opts and open imgs_dir for this iterations.
    ret = setup_images_dir (iteration, false, true);
    if (ret < 0) {
        pr_perror ("Error while setting up image directory (%d)", iteration);
        goto err;
    }

    if (pipe(cxfer.p)) {
        pr_perror("Can't make pipe for xfer");
        ret = -1;
        goto err;
    }
    cxfer.pipe_size = fcntl(cxfer.p[0], F_GETPIPE_SZ, 0);

    // Receive all dump info files in this iteration.
    while (!done) {

        struct xfer_metadata metadata;
        int ftype;
        void *buf = NULL;
        ret = -1;

        // Receive the file type from the sender node.
        ret = xfer_receive_one_dump (sk, -1, &metadata, sizeof(metadata), MSG_WAITALL, NULL);
        if (ret < 0) {
            pr_perror ("Error while receiving dump file metadata\n");
            goto err;
        }
        ftype = metadata.type;

        // See whether RunC dumped file (descriptors.json) is being sent from
        // the sender.
        if (ftype == CR_FD_XF_REQ_DESCRIPTORS_JSON) {

            ret = xfer_receive_runc_dump (sk, &metadata);
            if (ret < 0) {
                pr_perror ("Error while receiving runc dump!!!\n");
                goto err;
            }

            // Go for next command.
            continue;

        }

        // See whether dump-info bitmap is being sent in pre-dump round from
        // the sender.
        if (ftype == CR_FD_XF_REQ_DINFO_BITMAP) {
            // Receive the dump-info bitmap.
            ret = xfer_receive_one_dump (sk, ftype, &cr_dinfo_bitmap
                    , sizeof(cr_dinfo_bitmap), MSG_WAITALL, NULL);
            if (ret < 0) {
                pr_perror ("Error while receiving dump-info bitmap!!!\n");
                goto err;
            }

            // Go for next command.
            continue;
        }

        // See whether CR_FD_XF_REQ_IOV_PARENT is coming in pre-dump round from
        // the sender.
        if (ftype == CR_FD_XF_REQ_IOV_PARENT) {
            struct page_server_iov pi;
            pi.dst_id = metadata.dst_id;
            ret = page_server_check_parent (sk, &pi);

            // Go for next command.
            continue;
        }

        // See whether pages are going to be transferred.
        if (ftype == CR_FD_XF_REQ_PAGEMAP_AND_PAGES) {

            int k;
            if (opts.no_prestore)
                goto skip_prestore;

            // XXX: Shiv
            // Close all the images for this iteration except pagemaps, and pages
            // with the assumption that these images are the only images that
            // will be sent at the end.
            for (k = 0; k < CR_FD_MAX; k++) {
                if (dump_imgs[iteration - 1][k] && k != CR_FD_PAGEMAP && k != CR_FD_PAGES)
                    close_image(dump_imgs[iteration - 1][k]);
                dump_imgs[iteration - 1][k] = NULL;
            }
	    if (iteration < opts.rp)
		    goto skip_prestore;

            // Now start the parallel restore according to the provided --rp
            // (restoration point) argument if it the first time else signal
            // the parallel restore task to start the processing for successive
            // iteration.
            if (iteration == opts.rp) {
                if (__start_prestore_direct()) {
                    ret = -1;
                    pr_perror ("Error in starting parallel restore!!!\n");
                    goto err;
                }
                prestore_started = 1;

                // Give restoration_point appropriate values ( <= 1) to avoid
                // opening of parent directories.
                restoration_point = 0;

            } else {
                if (__signal_prestore(0)) {
                    ret = -1;
                    pr_perror ("Error while signaling parallel restore for "
                        "successive iteration!!!\n");
                    return -1;
                }

		// Set opts.auto_dedup to 0 so that xfer server don't punch holes
		opts.auto_dedup = 0;
            }

skip_prestore:
            if (xfer_receive_pages_dumps (sk) != 0) {
                pr_perror ("Error while receiving pages (%d)\n", ftype);
                ret = -1;
                goto err;
            }
            pr_debug ("All pages and pagemaps are received (%d)\n", ftype);

            // Go for next dump transfer.
            continue;
        }

        // See whether it is the transfer completion indicator.
        if (ftype == CR_FD_XF_REQ_NO_FILE) {
			int32_t status = 0;
            done = 1;
            /*
             * An answer must be sent back to inform another side,
             * that all data were received
             */
            if (__send(sk, &status, sizeof(status), 0) != sizeof(status)) {
                pr_perror("Can't send the final status");
                ret = -1;
            }
			tcp_nodelay (sk, true);

            continue;
        }

        // Now receive other dump file and close image file if it is not opened
        // by previous dump request from sender.
        //
        // TODO: Shiv
        // Here you can do the hybrid space allocation (static and dynamic) as
        // it is done inside "pb_write_one_buf" function [INTELLIGENT].
        //
        BUG_ON (ftype >= CR_FD_MAX);
        buf = xmalloc (metadata.size);
        if (!buf) {
            ret = -1;
            goto err;
        }
        done = xfer_receive_other_dumps (&dump_imgs[iteration - 1][ftype], sk
                , buf, &metadata);

        if (done < 0) {
            ret = -1;
            goto err;
        }

    } // while loop.
    
    ret = (done == 1) ? 0 : ret;
    if (ret == 0 && opts.ps_socket == -1) {
        char c;

        /*
         * Wait when a remote side closes the connection
         * to avoid TIME_WAIT bucket
         */
        if (read(sk, &c, sizeof(c)) != 0) {
            pr_perror("Unexpected data");
            ret = -1;
        }
    }

err:
    // Free page-server related structure and restore it like it was
    // initially. Close socket and return.
    page_server_close();
    close_image_dir();
    if (ret == 0) {
    	gettimeofday(&t, NULL);
    	pr_debug ("xfer-server: %dth iteration completed (timestamp: %ld.%ld).\n", iteration, t.tv_sec, t.tv_usec);
    } else {
    	gettimeofday(&t, NULL);
    	pr_perror ("xfer-server: %dth iteration failed!!! (timestamp: %ld.%ld)\n", iteration, t.tv_sec, t.tv_usec);
    }

    return ret;

}

static int fill_page_pipe(struct page_read *pr, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	int i, ret;

	pr->reset(pr);

	while (pr->advance(pr)) {
		unsigned long vaddr = pr->pe->vaddr;

		for (i = 0; i < pr->pe->nr_pages; i++, vaddr += PAGE_SIZE) {
			if (pagemap_in_parent(pr->pe))
				ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			else
				ret = page_pipe_add_page(pp, vaddr, pagemap_lazy(pr->pe) ? PPB_LAZY : 0);
			if (ret) {
				pr_err("Failed adding page at %lx\n", vaddr);
				return -1;
			}
		}
	}

	list_for_each_entry(ppb, &pp->bufs, l) {
		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];

			if (splice(img_raw_fd(pr->pi), NULL, ppb->p[1], NULL, iov.iov_len, SPLICE_F_MOVE) !=
			    iov.iov_len) {
				pr_perror("Splice failed");
				return -1;
			}
		}
	}

	debug_show_page_pipe(pp);

	return 0;
}

static int page_pipe_from_pagemap(struct page_pipe **pp, int pid)
{
	struct page_read pr;
	int nr_pages = 0;

    pr.is_pagemaps_cached = true;
	if (open_page_read(pid, &pr, PR_TASK) <= 0) {
		pr_err("Failed to open page read for %d\n", pid);
		return -1;
	}

	while (pr.advance(&pr))
		if (pagemap_present(pr.pe))
			nr_pages += pr.pe->nr_pages;

	*pp = create_page_pipe(nr_pages, NULL, 0);
	if (!*pp) {
		pr_err("Cannot create page pipe for %d\n", pid);
		return -1;
	}

	if (fill_page_pipe(&pr, *pp))
		return -1;

	return 0;
}

static int page_server_init_send(void)
{
	struct pstree_item *pi;
	struct page_pipe *pp;

	BUILD_BUG_ON(sizeof(struct dmp_info) > sizeof(struct rst_info));

	if (prepare_dummy_pstree())
		return -1;

	for_each_pstree_item(pi) {
		if (prepare_dummy_task_state(pi))
			return -1;

		if (!task_alive(pi))
			continue;

		if (page_pipe_from_pagemap(&pp, vpid(pi))) {
			pr_err("%d: failed to open page-read\n", vpid(pi));
			return -1;
		}

		/*
		 * prepare_dummy_pstree presumes 'restore' behaviour,
		 * but page_server_get_pages uses dmpi() to get access
		 * to the page-pipe, so we are faking it here.
		 */
        
        memset(rsti(pi), 0, sizeof(struct rst_info));
		dmpi(pi)->mem_pp = pp;
	}

	return 0;
}

int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd)
{
	struct timeval t;
	int ask = -1;
	int sk = -1;
	int ret;

	gettimeofday(&t, NULL);
	pr_info("Page Server started (timestamp: %ld.%ld)\n", t.tv_sec, t.tv_usec);

	if (init_stats(DUMP_STATS))
		return -1;

	if (!opts.lazy_pages)
		up_page_ids_base();
	else if (!lazy_dump)
		if (page_server_init_send())
			return -1;

	if (opts.ps_socket != -1) {
		ask = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", ask);
		goto no_server;
	}

	sk = setup_tcp_server("page", opts.addr, &opts.port);
	if (sk == -1)
		return -1;
no_server:

	if (!daemon_mode && cfd >= 0) {
		struct ps_info info = { .pid = getpid(), .port = opts.port };
		int count;

		count = write(cfd, &info, sizeof(info));
		close_safe(&cfd);
		if (count != sizeof(info)) {
			pr_perror("Unable to write ps_info");
			exit(1);
		}
	}

	ret = run_tcp_server(daemon_mode, &ask, cfd, sk);
	if (ret != 0)
		return ret > 0 ? 0 : -1;

	if (tls_x509_init(ask, true)) {
		close_safe(&sk);
		return -1;
	}

	if (ask >= 0)
		ret = page_server_serve(ask);

	gettimeofday(&t, NULL);
	pr_info("Page Server finished (timestamp: %ld.%ld)\n", t.tv_sec, t.tv_usec);

	if (daemon_mode)
		exit(ret);

	return ret;
}

/**
 * Shiv:
 * Function to listen to socket @sk and accept connection from the client.
 * Return value:
 *      0   -> on success and @ask will point to the accepting socket.
 *      -1  -> on some error.
 */
static inline int xfer_get_connection (int *ask, int sk) {

    struct sockaddr_in caddr;
    socklen_t clen = sizeof (caddr);

    if (listen (sk, 1)) {
        pr_perror ("Can't listen on xfer-server socket");
        close (sk);
        return -1;
    }

    *ask = accept (sk, (struct sockaddr *)&caddr, &clen);
    if (*ask < 0) {
        pr_perror("Can't accept connection to xfer-server");
        return -1;
    } else {
        pr_info ("Accepted connection from %s:%u\n", inet_ntoa(caddr.sin_addr),
            (int)ntohs(caddr.sin_port));
    }

    return 0;

}

// The code is same as cr_page_server with some modifications.
int cr_xfer_server () {

	struct timeval t;
    	int ask = -1;
	int sk = -1;
	int ret, i, j;

	gettimeofday(&t, NULL);
	pr_info("Xfer Server started (timestamp: %ld.%ld)\n", t.tv_sec, t.tv_usec);

	if (init_stats(DUMP_STATS))
		return -1;
    
    // Shiv:
    // This is by default in xfer-server since we don't support lazy dumping
    // (it is necessary from the comment of up_page_ids_base() code.)
    up_page_ids_base();

	sk = setup_tcp_server("xfer", opts.addr, &opts.port);
	if (sk == -1) {
        pr_err ("Not able to setup xfer-server\n");
		return -1;
    }

	ret = status_ready ();
	if (ret < 0) {
		ret = -1;
        goto err;
    }
    ret = 0;

    // Give restoration_point appropriate values ( > 1) to open parent directories.
    restoration_point = 2;

    // Accept connection from the client in each iterationi, do tls handshake
    // and then start serving the client.
    for (i = 0; i < opts.iterations; i++) {

        unsigned long old_page_ids = page_ids;

        dump_imgs[i] = (struct cr_img **) xmalloc (CR_FD_MAX * sizeof(struct cr_img *));
        if (!dump_imgs[i])
            goto err;
        for (j = 0; j < CR_FD_MAX; j++)
            dump_imgs[i][j] = NULL;

        ret = xfer_get_connection (&ask, sk);
        if (ret < 0)
            goto err;

        if (tls_x509_init (ask, true)) {
            ret = -1;
            goto err;
        }

        ret = xfer_server_serve (ask, (i + 1));
        if (ret < 0) {
            pr_perror ("Some error during %dth iteration\n", (i + 1));
            goto err;
        }

        // Close the images for this iteration.
        for (j = 0; j < CR_FD_MAX; j++) {
            if (dump_imgs[i][j])
                close_image(dump_imgs[i][j]);
            dump_imgs[i][j] = NULL;
        }
        xfree (dump_imgs[i]);
        dump_imgs[i] = NULL;

        // Restore page ids for next iteration to generate same pagemap and pages
        // image files.
        page_ids = old_page_ids;

    }

err:
    tls_terminate_session();
    close_image_root_dir();
    close_all_images();
    pr_info ("Session over\n");

    close_safe(&sk);

    gettimeofday(&t, NULL);
    pr_info("Xfer Server finished (timestamp: %ld.%ld)\n", t.tv_sec, t.tv_usec);

    return ret;

}

static int connect_to_page_server(void)
{
	if (!opts.use_page_server)
		return 0;

	if (opts.ps_socket != -1) {
		page_server_sk = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", page_server_sk);
		goto out;
	}

	page_server_sk = setup_tcp_client(opts.addr);
	if (page_server_sk == -1)
		return -1;

	if (tls_x509_init(page_server_sk, false)) {
		close(page_server_sk);
		return -1;
	}
out:
	/*
	 * CORK the socket at the very beginning. As per ANK
	 * the corked by default socket with sporadic NODELAY-s
	 * on urgent data is the smartest mode ever.
	 */
	tcp_cork(page_server_sk, true);
	return 0;
}

// It connect to xfer-server if --xfer-server option is specified.
static int connect_to_xfer_server (void) {

	if (!opts.use_xfer_server)
		return 0;

	xfer_server_sk = setup_tcp_client(opts.addr);
	if (xfer_server_sk == -1)
		return -1;

    // Shiv:
    // Trick to use existing page-server setup.
    page_server_sk = xfer_server_sk;
    opts.use_page_server = opts.use_xfer_server;

    // TLS
	if (tls_x509_init(xfer_server_sk, false)) {
		close(xfer_server_sk);
		return -1;
	}
	
    /*
	 * CORK the socket at the very beginning. As per ANK
	 * the corked by default socket with sporadic NODELAY-s
	 * on urgent data is the smartest mode ever.
	 */
	tcp_cork(xfer_server_sk, true);
	return 0;
}

int connect_to_xfer_server_to_send (void) {

    // Shiv:
    // Connect to page server if --page-server is specified else connect
    // to xfer-server.
	if (opts.use_xfer_server)
	    return connect_to_xfer_server();
    else
        return connect_to_page_server();

}

int send_runc_descriptors_file_xfer_server (void) {

    struct xfer_metadata xfer_meta;
    struct stat st;
    int dirfd = -1;
    int ret = -1;
    int fd = -1;

    // Send descriptors.json file dumped from RunC only when --xfer-server
    // option is supplied.
    if (!opts.use_xfer_server)
        return 0;

    // Open the runc dump file (descriptors.json file).
    dirfd = get_service_fd (IMG_FD_OFF);
    if (dirfd < 0)
        return -1;
    fd = openat (dirfd, "descriptors.json", O_RDONLY);
    if (fd < 0)
        return -1;

    // Now get the file size.
    if (fstat (fd, &st) < 0) {
        pr_perror("Can't fstat opened file");
        close (fd);
        return -1;
    }

    // And finally send this file to destination.
    xfer_meta.type = CR_FD_XF_REQ_DESCRIPTORS_JSON;
    xfer_meta.size = st.st_size;
    xfer_meta.save_method = CR_IMG_RAW;
    strcpy (xfer_meta.img_name, "descriptors.json");
    ret = send_to_xfer_server_fd (&xfer_meta, fd);
    close (fd);
    return ret;

}

int disconnect_from_page_server(void)
{
	struct page_server_iov pi = {};
	int32_t status = -1;
	int ret = -1;

	if (!opts.use_page_server)
		return 0;

	if (page_server_sk == -1)
		return 0;

	pr_info("Disconnect from the page server\n");

	if (opts.ps_socket != -1)
		/*
		 * The socket might not get closed (held by
		 * the parent process) so we must order the
		 * page-server to terminate itself.
		 */
		pi.cmd = PS_IOV_FLUSH_N_CLOSE;
	else
		pi.cmd = PS_IOV_FLUSH;

	if (send_psi(page_server_sk, &pi))
		goto out;

	tcp_nodelay(page_server_sk, true);

	if (__recv(page_server_sk, &status, sizeof(status), MSG_WAITALL) != sizeof(status)) {
		pr_perror("The page server doesn't answer");
		goto out;
	}

	ret = 0;
out:
	tls_terminate_session();
	close_safe(&page_server_sk);

	return ret ?: status;
}

int disconnect_from_xfer_server (void) {

    struct xfer_metadata xfer_meta;
	int ret = -1;
	int32_t status = -1;

	if (!(opts.use_xfer_server || opts.use_page_server))
		return 0;

	if (xfer_server_sk == -1)
		return 0;

	pr_info("Disconnect from the xfer server\n");

    xfer_meta.type = CR_FD_XF_REQ_NO_FILE;
    xfer_meta.size = 0;
    strcpy(xfer_meta.img_name, "no-file.img");

    if (send_metadata_xfer_server (xfer_server_sk, &xfer_meta) < 0) {
        pr_perror ("Can't send completion indication to xfer-server\n");
        goto out;
    }
	pr_debug ("Completion command for all data transfer is sent to xfer-server\n");

    if (__recv(xfer_server_sk, &status, sizeof(status), MSG_WAITALL) != sizeof(status)) {
        pr_perror("The xfer server doesn't answer");
        goto out;
    }

	ret = 0;

out:
	tls_terminate_session();
	close_safe(&xfer_server_sk);

	return ret;

}

struct ps_async_read {
	unsigned long rb; /* read bytes */
	unsigned long goal;
	unsigned long nr_pages;

	struct page_server_iov pi;
	void *pages;

	ps_async_read_complete complete;
	void *priv;

	struct list_head l;
};

static LIST_HEAD(async_reads);

static inline void async_read_set_goal(struct ps_async_read *ar, int nr_pages)
{
	ar->goal = sizeof(ar->pi) + nr_pages * PAGE_SIZE;
	ar->nr_pages = nr_pages;
}

static void init_ps_async_read(struct ps_async_read *ar, void *buf, int nr_pages, ps_async_read_complete complete,
			       void *priv)
{
	ar->pages = buf;
	ar->rb = 0;
	ar->complete = complete;
	ar->priv = priv;
	async_read_set_goal(ar, nr_pages);
}

static int page_server_start_async_read(void *buf, int nr_pages, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read *ar;

	ar = xmalloc(sizeof(*ar));
	if (ar == NULL)
		return -1;

	init_ps_async_read(ar, buf, nr_pages, complete, priv);
	list_add_tail(&ar->l, &async_reads);
	return 0;
}

/*
 * There are two possible event types we need to handle:
 * - page info is available as a reply to request_remote_page
 * - page data is available, and it follows page info we've just received
 * Since the on dump side communications are completely synchronous,
 * we can return to epoll right after the reception of page info and
 * for sure the next time socket event will occur we'll get page data
 * related to info we've just received
 */
static int page_server_read(struct ps_async_read *ar, int flags)
{
	int ret, need;
	void *buf;

	if (ar->rb < sizeof(ar->pi)) {
		/* Header */
		buf = ((void *)&ar->pi) + ar->rb;
		need = sizeof(ar->pi) - ar->rb;
	} else {
		/* page-serer may return less pages than we asked for */
		if (ar->pi.nr_pages < ar->nr_pages)
			async_read_set_goal(ar, ar->pi.nr_pages);
		/* Page(s) data itself */
		buf = ar->pages + (ar->rb - sizeof(ar->pi));
		need = ar->goal - ar->rb;
	}

	ret = __recv(page_server_sk, buf, need, flags);
	if (ret < 0) {
		if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR)) {
			ret = 0;
		} else {
			pr_perror("Error reading data from page server");
			return -1;
		}
	}

	ar->rb += ret;
	if (ar->rb < ar->goal)
		return 1;

	/*
	 * IO complete -- notify the caller and drop the request
	 */
	BUG_ON(ar->rb > ar->goal);
	return ar->complete((int)ar->pi.dst_id, (unsigned long)ar->pi.vaddr, (int)ar->pi.nr_pages, ar->priv);
}

static int page_server_async_read(struct epoll_rfd *f)
{
	struct ps_async_read *ar;
	int ret;

	BUG_ON(list_empty(&async_reads));
	ar = list_first_entry(&async_reads, struct ps_async_read, l);
	ret = page_server_read(ar, MSG_DONTWAIT);

	if (ret > 0)
		return 0;
	if (!ret) {
		list_del(&ar->l);
		xfree(ar);
	}

	return ret;
}

static int page_server_hangup_event(struct epoll_rfd *rfd)
{
	pr_err("Remote side closed connection\n");
	return -1;
}

static struct epoll_rfd ps_rfd;

int connect_to_page_server_to_recv(int epfd)
{
	if (connect_to_page_server())
		return -1;

	ps_rfd.fd = page_server_sk;
	ps_rfd.read_event = page_server_async_read;
	ps_rfd.hangup_event = page_server_hangup_event;

	return epoll_add_rfd(epfd, &ps_rfd);
}

int request_remote_pages(unsigned long img_id, unsigned long addr, int nr_pages)
{
	struct page_server_iov pi = {
		.cmd = PS_IOV_GET,
		.nr_pages = nr_pages,
		.vaddr = addr,
		.dst_id = img_id,
	};

	/* XXX: why MSG_DONTWAIT here? */
	if (send_psi_flags(page_server_sk, &pi, MSG_DONTWAIT))
		return -1;

	tcp_nodelay(page_server_sk, true);
	return 0;
}

static int page_server_start_sync_read(void *buf, int nr, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read ar;
	int ret = 1;

	init_ps_async_read(&ar, buf, nr, complete, priv);
	while (ret == 1)
		ret = page_server_read(&ar, MSG_WAITALL);
	return ret;
}

int page_server_start_read(void *buf, int nr, ps_async_read_complete complete, void *priv, unsigned flags)
{
	if (flags & PR_ASYNC)
		return page_server_start_async_read(buf, nr, complete, priv);
	else
		return page_server_start_sync_read(buf, nr, complete, priv);
}
