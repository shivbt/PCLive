#include <unistd.h>
#include <linux/memfd.h>

#include "common/compiler.h"
#include "common/lock.h"
#include "memfd.h"
#include "fdinfo.h"
#include "imgset.h"
#include "image.h"
#include "util.h"
#include "log.h"
#include "files.h"
#include "fs-magic.h"
#include "kerndat.h"
#include "files-reg.h"
#include "rst-malloc.h"
#include "rst-fmalloc.h"
#include "fdstore.h"
#include "file-ids.h"
#include "namespaces.h"
#include "shmem.h"

#include "protobuf.h"
#include "images/memfd.pb-c.h"
#include "prestore.h"

#define MEMFD_PREFIX	 "/memfd:"
#define MEMFD_PREFIX_LEN (sizeof(MEMFD_PREFIX) - 1)

#define F_SEAL_SEAL   0x0001 /* prevent further seals from being set */
#define F_SEAL_SHRINK 0x0002 /* prevent file from shrinking */
#define F_SEAL_GROW   0x0004 /* prevent file from growing */
#define F_SEAL_WRITE  0x0008 /* prevent writes */
/* Linux 5.1+ */
#define F_SEAL_FUTURE_WRITE 0x0010 /* prevent future writes while mapped */

struct memfd_dump_inode {
	struct list_head list;
	u32 id;
	u32 dev;
	u32 ino;
};

struct memfd_restore_inode {
	struct list_head list;
	mutex_t lock;
	int fdstore_id;
    bool is_deleted;
	unsigned int pending_seals;
	MemfdInodeEntry *mie;
};

struct list_head *memfd_inodes;

int memfd_inodes_init (bool is_restore) {

    int ret = 1;

    if (is_restore)
        memfd_inodes = fshmalloc (sizeof (*memfd_inodes));
    else
        memfd_inodes = xmalloc (sizeof (*memfd_inodes));

    if (memfd_inodes == NULL)
        goto err;

    memfd_inodes->prev = memfd_inodes;
    memfd_inodes->next = memfd_inodes;
    ret = 0;

err:
    return ret;

}

/*
 * Dump only
 */

static u32 memfd_inode_ids = 1;

int is_memfd(dev_t dev)
{
	/*
	 * TODO When MAP_HUGETLB is used, the file device is not shmem_dev,
	 * Note that other parts of CRIU have similar issues, see
	 * is_anon_shmem_map().
	 */
	return dev == kdat.shmem_dev;
}

static int dump_memfd_inode(int fd, struct memfd_dump_inode *inode, const char *name, const struct stat *st)
{
	MemfdInodeEntry mie = MEMFD_INODE_ENTRY__INIT;
	int ret = -1;
	u32 shmid;

	/*
	  * shmids are chosen as the inode number of the corresponding mmaped
	  * file. See handle_vma() in proc_parse.c.
	  * It works for memfd too, because we share the same device as the
	  * shmem device.
	  */
	shmid = inode->ino;

	pr_info("Dumping memfd:%s contents (id %#x, shmid: %#x, size: %" PRIu64 ")\n", name, inode->id, shmid,
		st->st_size);

	if (dump_one_memfd_shmem(fd, shmid, st->st_size) < 0)
		goto out;

	mie.inode_id = inode->id;
	mie.uid = userns_uid(st->st_uid);
	mie.gid = userns_gid(st->st_gid);
	mie.name = (char *)name;
	mie.size = st->st_size;
	mie.shmid = shmid;

	mie.seals = fcntl(fd, F_GET_SEALS);
	if (mie.seals == -1)
		goto out;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_MEMFD_INODE), &mie, PB_MEMFD_INODE))
		goto out;

	ret = 0;

out:
	return ret;
}

static struct memfd_dump_inode *dump_unique_memfd_inode(int lfd, const char *name, const struct stat *st)
{
	struct memfd_dump_inode *inode;
	int fd;

	list_for_each_entry(inode, memfd_inodes, list)
		if ((inode->dev == st->st_dev) && (inode->ino == st->st_ino))
			return inode;

	inode = xmalloc(sizeof(*inode));
	if (inode == NULL)
		return NULL;

	inode->dev = st->st_dev;
	inode->ino = st->st_ino;
	inode->id = memfd_inode_ids++;

	fd = open_proc(PROC_SELF, "fd/%d", lfd);
	if (fd < 0) {
		xfree(inode);
		return NULL;
	}

	if (dump_memfd_inode(fd, inode, name, st)) {
		close(fd);
		xfree(inode);
		return NULL;
	}
	close(fd);

	list_add_tail(&inode->list, memfd_inodes);

	return inode;
}

static int dump_one_memfd(int lfd, u32 id, const struct fd_parms *p)
{
	MemfdFileEntry mfe = MEMFD_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct memfd_dump_inode *inode;
	struct fd_link _link, *link;
	const char *name;

	if (!p->link) {
		if (fill_fdlink(lfd, p, &_link))
			return -1;
		link = &_link;
	} else
		link = p->link;

	link_strip_deleted(link);
	/* link->name is always started with "." which has to be skipped.  */
	if (strncmp(link->name + 1, MEMFD_PREFIX, MEMFD_PREFIX_LEN) == 0)
		name = &link->name[1 + MEMFD_PREFIX_LEN];
	else
		name = link->name + 1;

	inode = dump_unique_memfd_inode(lfd, name, &p->stat);
	if (!inode)
		return -1;

	mfe.id = id;
	mfe.flags = p->flags;
	mfe.pos = p->pos;
	mfe.fown = (FownEntry *)&p->fown;
	mfe.inode_id = inode->id;

	fe.type = FD_TYPES__MEMFD;
	fe.id = mfe.id;
	fe.memfd = &mfe;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

int dump_one_memfd_cond(int lfd, u32 *id, struct fd_parms *parms)
{
	if (fd_id_generate_special(parms, id))
		return dump_one_memfd(lfd, *id, parms);
	return 0;
}

const struct fdtype_ops memfd_dump_ops = {
	.type = FD_TYPES__MEMFD,
	.dump = dump_one_memfd,
};

/*
 * Restore only
 */

struct memfd_info {
	MemfdFileEntry *mfe;
	struct file_desc d;
	struct memfd_restore_inode *inode;
};

static struct memfd_restore_inode *memfd_alloc_inode(int id)
{
	struct memfd_restore_inode *inode;

	list_for_each_entry(inode, memfd_inodes, list)
		if (inode->mie->inode_id == id)
			return inode;

	pr_err("Unable to find the %d memfd inode\n", id);
	return NULL;
}

// Function to check whether a memfd inode entry is already present from
// the previous iteration.
static int search_and_update_one_memfd_inode (ProtobufCMessage *base) {

    struct memfd_restore_inode *inode;
    MemfdInodeEntry *mie = pb_msg (base, MemfdInodeEntry);

    // Search it.
    if (likely (memfd_inodes != NULL)) {
        list_for_each_entry (inode, memfd_inodes, list) {
            if (inode->mie->inode_id == mie->inode_id) {
                inode->mie = mie;
                inode->is_deleted = false;
                return 1;
            }
        }
    }

    // The entry is not found.
    return 0;

}

static int collect_one_memfd_inode (void *o, ProtobufCMessage *base
        , struct cr_img *i) {

	MemfdInodeEntry *mie = pb_msg(base, MemfdInodeEntry);
	struct memfd_restore_inode *inode = o;

	inode->mie = mie;
	mutex_init(&inode->lock);
	inode->fdstore_id = -1;
	inode->pending_seals = 0;
    inode->is_deleted = false;

	list_add_tail(&inode->list, memfd_inodes);

	return 0;

}

static struct collect_image_info memfd_inode_cinfo = {
	.fd_type = CR_FD_MEMFD_INODE,
	.pb_type = PB_MEMFD_INODE,
	.priv_size = sizeof(struct memfd_restore_inode),
    .search_and_update = search_and_update_one_memfd_inode,
	.collect = collect_one_memfd_inode,
	.flags = COLLECT_SHARED | COLLECT_NOFREE,
    .info_type = PRST_INFO_GLOBAL,
};

static inline int init_or_reset_memfd_inodes (int init_iter) {

    struct memfd_restore_inode *inode;
    if (init_iter && memfd_inodes_init(true))
        return 1;

    // Remove collect happened flag.
    memfd_inode_cinfo.flags &= ~COLLECT_HAPPENED;

    // Mark every info as deleted before the processing for this iteration.
    list_for_each_entry (inode, memfd_inodes, list)
        inode->is_deleted = true;

    return 0;

}

static inline void clean_memfd_inodes (bool init_iter) {

    struct memfd_restore_inode *inode;
    if (init_iter)
        return;

    // Clean entries from memfd_inodes list which was present in previous
    // iteration but not present in current iteration.
    list_for_each_entry (inode, memfd_inodes, list)
        if (inode->is_deleted)
            fshfree_last (inode);

}

int prepare_memfd_inodes (bool init_iter) {

    int ret = 1;
    if (init_or_reset_memfd_inodes (init_iter))
        goto err;
    ret = collect_image(&memfd_inode_cinfo);
    clean_memfd_inodes (init_iter);
    ret = 0;

err:
    return ret;

}

static int memfd_open_inode_nocache(struct vma_area *vma, struct memfd_restore_inode *inode)
{
	MemfdInodeEntry *mie = NULL;
	int fd = -1;
	int ret = -1;
	int flags;

	mie = inode->mie;
	if (mie->seals == F_SEAL_SEAL) {
		inode->pending_seals = 0;
		flags = 0;
	} else {
		/* Seals are applied later due to F_SEAL_FUTURE_WRITE */
		inode->pending_seals = mie->seals;
		flags = MFD_ALLOW_SEALING;
	}

	fd = memfd_create(mie->name, flags);
	if (fd < 0) {
		pr_perror("Can't create memfd:%s", mie->name);
		goto out;
	}

	if (restore_memfd_shmem_content(vma, fd, mie->shmid, mie->size))
		goto out;

	if (fchown(fd, mie->uid, mie->gid)) {
		pr_perror("Can't change uid %d gid %d of memfd:%s", (int)mie->uid, (int)mie->gid, mie->name);
		goto out;
	}

	inode->fdstore_id = fdstore_add(fd);
	if (inode->fdstore_id < 0)
		goto out;

	ret = fd;
	fd = -1;

out:
	if (fd != -1)
		close(fd);
	return ret;
}

static int memfd_open_inode(struct vma_area *vma, struct memfd_restore_inode *inode)
{
	int fd;

	if (inode->fdstore_id != -1)
		return fdstore_get(inode->fdstore_id);

	mutex_lock(&inode->lock);
	if (inode->fdstore_id != -1)
		fd = fdstore_get(inode->fdstore_id);
	else
		fd = memfd_open_inode_nocache(vma, inode);
	mutex_unlock(&inode->lock);

	return fd;
}

int memfd_open(struct vma_area *vma, struct file_desc *d, u32 *fdflags)
{
	struct memfd_info *mfi;
	MemfdFileEntry *mfe;
	int fd, _fd;
	u32 flags;

	mfi = container_of(d, struct memfd_info, d);
	mfe = mfi->mfe;

	if (inherited_fd(d, &fd))
		return fd;

	pr_info("Restoring memfd id=%d\n", mfe->id);

	fd = memfd_open_inode(vma, mfi->inode);
	if (fd < 0)
		goto err;

	/* Reopen the fd with original permissions */
	flags = fdflags ? *fdflags : mfe->flags;
	/*
	 * Ideally we should call compat version open() to not force the
	 * O_LARGEFILE file flag with regular open(). It doesn't seem that
	 * important though.
	 */
	_fd = __open_proc(PROC_SELF, 0, flags, "fd/%d", fd);
	if (_fd < 0) {
		pr_perror("Can't reopen memfd id=%d", mfe->id);
		goto err;
	}
	close(fd);
	fd = _fd;

	if (restore_fown(fd, mfe->fown) < 0)
		goto err;

	if (lseek(fd, mfe->pos, SEEK_SET) < 0) {
		pr_perror("Can't restore file position of memfd id=%d", mfe->id);
		goto err;
	}

	return fd;

err:
	if (fd >= 0)
		close(fd);
	return -1;
}

static int memfd_open_fe_fd(struct file_desc *fd, int *new_fd)
{
	int tmp;

	tmp = memfd_open(NULL, fd, NULL);
	if (tmp < 0)
		return -1;
	*new_fd = tmp;
	return 0;
}

static char *memfd_d_name(struct file_desc *d, char *buf, size_t s)
{
	MemfdInodeEntry *mie = NULL;
	struct memfd_info *mfi;

	mfi = container_of(d, struct memfd_info, d);

	mie = mfi->inode->mie;
	if (snprintf(buf, s, "%s%s", MEMFD_PREFIX, mie->name) >= s) {
		pr_err("Buffer too small for memfd name %s\n", mie->name);
		return NULL;
	}

	return buf;
}

static struct file_desc_ops memfd_desc_ops = {
	.type = FD_TYPES__MEMFD,
	.open = memfd_open_fe_fd,
	.name = memfd_d_name,
};

// Function to check whether a memfd file entry is already present from
// the previous iteration.
static int search_and_update_one_memfd (ProtobufCMessage *base) {

    struct memfd_info *info;
    MemfdFileEntry *mfe;
    struct file_desc *d;
    unsigned int id;
    int type;

    // Decode the image and get id & type.
    mfe = pb_msg (base, MemfdFileEntry);
    id = mfe->id;
    type = (&memfd_desc_ops)->type;

    // Search for this id and type.
    d = find_file_desc_raw (type, id);
    if (d != NULL) {
        info = container_of (d, struct memfd_info, d);
        info->mfe = mfe;
        return 1;
    }

    // Not found.
    return 0;

}

static int collect_one_memfd(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct memfd_info *info = o;

	info->mfe = pb_msg(msg, MemfdFileEntry);
	info->inode = memfd_alloc_inode(info->mfe->inode_id);
	if (!info->inode)
		return -1;

	return file_desc_add(&info->d, info->mfe->id, &memfd_desc_ops);
}

struct collect_image_info memfd_cinfo = {
	.fd_type = CR_FD_MEMFD_FILE,
	.pb_type = PB_MEMFD_FILE,
	.priv_size = sizeof(struct memfd_info),
    .search_and_update = search_and_update_one_memfd,
	.collect = collect_one_memfd,
    .info_type = PRST_INFO_GLOBAL,
};

struct file_desc *collect_memfd(u32 id)
{
	struct file_desc *fdesc;

	fdesc = find_file_desc_raw(FD_TYPES__MEMFD, id);
	if (fdesc == NULL)
		pr_err("No entry for memfd %#x\n", id);

	return fdesc;
}

int apply_memfd_seals(void)
{
	/*
	 * We apply the seals after all the mappings are done because the seal
	 * F_SEAL_FUTURE_WRITE prevents future write access (added in
	 * Linux 5.1). Thus we must make sure all writable mappings are opened
	 * before applying this seal.
	 */

	int ret, fd;
	struct memfd_restore_inode *inode;

	list_for_each_entry(inode, memfd_inodes, list) {
		if (!inode->pending_seals)
			continue;

		fd = memfd_open_inode(NULL, inode);
		if (fd < 0)
			return -1;

		ret = fcntl(fd, F_ADD_SEALS, inode->pending_seals);
		close(fd);

		if (ret < 0) {
			pr_perror("Cannot apply seals on memfd");
			return -1;
		}
	}

	return 0;
}
