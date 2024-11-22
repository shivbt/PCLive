#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include "imgset.h"
#include "image.h"
#include "files.h"
#include "files-reg.h"
#include "file-ids.h"
#include "pipes.h"

#include "fifo.h"

#include "protobuf.h"
#include "images/regfile.pb-c.h"
#include "images/fifo.pb-c.h"
#include "prestore.h"
#include "rst-fmalloc.h"

/*
 * FIFO checkpoint and restore is done in a bit unusual manner.
 * We use files-reg.c engine to save fifo path and flags,
 * thus regular files image will contain fifo descriptors which
 * are useless for reg-files engine itself but needed for our fifo
 * engine.
 *
 * In particular we dump fifo-entry automatically and appropriate
 * reg-file entry manually, thus on restore we need to ask reg-file
 * engine to restore fifo path and flags via direct call.
 */

struct fifo_info {
	struct list_head list;
	struct file_desc d;
	FifoEntry *fe;
	bool restore_data;
};

static struct list_head *fifo_head = NULL;

static struct pipe_data_dump pd_fifo = {
	.img_type = CR_FD_FIFO_DATA,
};

int fifo_head_shalloc (void) {

    fifo_head = fshmalloc (sizeof (*fifo_head));
    if (fifo_head == NULL) {
        pr_perror ("Can't allocate from fixed shared space\n");
        return 1;
    }

    INIT_LIST_HEAD (fifo_head);
    return 0;

}

static int dump_one_fifo(int lfd, u32 id, const struct fd_parms *p)
{
	struct cr_img *img = img_from_set(glob_imgset, CR_FD_FILES);
	FileEntry fe = FILE_ENTRY__INIT;
	FifoEntry e = FIFO_ENTRY__INIT;
	u32 rf_id;

	fd_id_generate_special(NULL, &rf_id);

	/*
	 * It's a trick here, we use regular files dumping
	 * code to save path to a fifo, then we reuse it
	 * on restore.
	 */
	if (dump_one_reg_file(lfd, rf_id, p))
		return -1;

	pr_info("Dumping fifo %d with id %#x pipe_id %#x\n", lfd, id, pipe_id(p));

	e.id = id;
	e.pipe_id = pipe_id(p);
	e.has_regf_id = true;
	e.regf_id = rf_id;

	fe.type = FD_TYPES__FIFO;
	fe.id = e.id;
	fe.fifo = &e;

	if (pb_write_one(img, &fe, PB_FILE))
		return -1;

	return dump_one_pipe_data(&pd_fifo, lfd, p);
}

const struct fdtype_ops fifo_dump_ops = {
	.type = FD_TYPES__FIFO,
	.dump = dump_one_fifo,
};

static struct pipe_data_rst **pd_hash_fifo = NULL;

int pd_hash_fifo_shalloc (void) {

    size_t size = sizeof (*pd_hash_fifo) * PIPE_DATA_HASH_SIZE;
    pd_hash_fifo = fshmalloc (size);
    if (pd_hash_fifo == NULL)
        goto err;

    memzero (pd_hash_fifo, size);
    return 0;

err:
    pr_perror ("Can't allocate from fixed shared space\n");
    return 1;

}

static int do_open_fifo(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	struct fifo_info *info = arg;
	int new_fifo, fake_fifo = -1;

	/*
	 * The fifos (except read-write fifos) do wait until
	 * another pipe-end get connected, so to be able to
	 * proceed the restoration procedure we open a fake
	 * fifo here.
	 */
	fake_fifo = openat(ns_root_fd, rfi->path, O_RDWR);
	if (fake_fifo < 0) {
		pr_perror("Can't open fake fifo %#x [%s]", info->fe->id, rfi->path);
		return -1;
	}

	new_fifo = openat(ns_root_fd, rfi->path, rfi->rfe->flags);
	if (new_fifo < 0) {
		pr_perror("Can't open fifo %#x [%s]", info->fe->id, rfi->path);
		goto out;
	}

	if (info->restore_data)
		if (restore_pipe_data(CR_FD_FIFO_DATA, fake_fifo, info->fe->pipe_id, pd_hash_fifo)) {
			close(new_fifo);
			new_fifo = -1;
		}

out:
	close(fake_fifo);
	return new_fifo;
}

static int open_fifo_fd(struct file_desc *d, int *new_fd)
{
	struct fifo_info *info = container_of(d, struct fifo_info, d);
	struct file_desc *reg_d;
	int fd;

	reg_d = collect_special_file(info->fe->has_regf_id ? info->fe->regf_id : info->fe->id);
	if (!reg_d)
		return -1;

	fd = open_path(reg_d, do_open_fifo, info);
	if (fd < 0)
		return -1;
	*new_fd = fd;
	return 0;
}

static struct file_desc_ops fifo_desc_ops = {
	.type = FD_TYPES__FIFO,
	.open = open_fifo_fd,
};

// Function to check whether fifo entry is already present from the
// previous iteration.
static int search_and_update_one_fifo (ProtobufCMessage *base) {

    FifoEntry *fe;
    unsigned int id;
    int type;

    // Decode the image and get id & type.
    fe = pb_msg (base, FifoEntry);
    id = fe->id;
    type = (&fifo_desc_ops)->type;

    // Search for this id and type.
    if (find_file_desc_raw (type, id) != NULL)
        return 1;

    // Not found.
    return 0;

}

static int collect_one_fifo (void *o, ProtobufCMessage *base, struct cr_img *i)
{
    struct fifo_info *info = o, *f;

	info->fe = pb_msg(base, FifoEntry);
	pr_info("Collected fifo entry ID %#x PIPE ID %#x\n", info->fe->id, info->fe->pipe_id);

	/* check who will restore the fifo data */
	list_for_each_entry(f, fifo_head, list)
		if (f->fe->pipe_id == info->fe->pipe_id)
			break;

	if (&f->list == fifo_head) {
		list_add(&info->list, fifo_head);
		info->restore_data = true;
	} else {
		INIT_LIST_HEAD(&info->list);
		info->restore_data = false;
	}

	return file_desc_add(&info->d, info->fe->id, &fifo_desc_ops);

}

struct collect_image_info fifo_cinfo = {
	.fd_type = CR_FD_FIFO,
	.pb_type = PB_FIFO,
	.priv_size = sizeof(struct fifo_info),
    .search_and_update = search_and_update_one_fifo,
	.collect = collect_one_fifo,
    .info_type = PRST_INFO_GLOBAL,
};

// Function to check whether a fifodata entry is already present from the
// previous iteration.
static int search_and_update_fifo_data (ProtobufCMessage *base) {

    struct pipe_data_rst *pd;
    PipeDataEntry *pde;
    int table_index;

    // Get the entry from protobuf and calculate table index.
    pde = pb_msg (base, PipeDataEntry);
    table_index = pde->pipe_id & PIPE_DATA_HASH_MASK;

    // Now search it.
    for (pd = pd_hash_fifo [table_index]; pd != NULL; pd = pd->next) {
        if (pd->pde->pipe_id == pde->pipe_id) {
            memcpy (pd->pde, pde, sizeof (*pde));
            return 1;
        }
    }

    // Not found.
    return 0;

}

static int collect_fifo_data(void *obj, ProtobufCMessage *msg, struct cr_img *img)
{
    return do_collect_pipe_data(obj, msg, img, pd_hash_fifo);
}

struct collect_image_info fifo_data_cinfo = {
	.fd_type = CR_FD_FIFO_DATA,
	.pb_type = PB_PIPE_DATA,
	.priv_size = sizeof(struct pipe_data_rst),
    .search_and_update = search_and_update_fifo_data,
	.collect = collect_fifo_data,
    .info_type = PRST_INFO_GLOBAL,
};
