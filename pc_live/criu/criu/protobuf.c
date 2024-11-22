#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <google/protobuf-c/protobuf-c.h>

#include "image.h"
#include "servicefd.h"
#include "common/compiler.h"
#include "log.h"
#include "rst-fmalloc.h"
#include "string.h"
#include "sockets.h"
#include "cr_options.h"
#include "bfd.h"
#include "protobuf.h"
#include "util.h"
#include "page-xfer.h"
#include "prestore.h"


#define image_name(img, buf) __image_name(img, buf, sizeof(buf))
static char *__image_name(struct cr_img *img, char *image_path, size_t image_path_size)
{
	int fd = img->_x.fd;

	if (lazy_image(img))
		return img->path;
	else if (empty_image(img))
		return "(empty-image)";
	else if (fd >= 0 && read_fd_link(fd, image_path, image_path_size) > 0)
		return image_path;

	return NULL;
}

/*
 * Reads PB record (header + packed object) from file @fd and unpack
 * it with @unpack procedure to the pointer @pobj
 *
 *  1 on success
 * -1 on error (or EOF met and @eof set to false)
 *  0 on EOF and @eof set to true
 *
 * Don't forget to free memory granted to unpacked object in calling code if needed
 */

int do_pb_read_one (struct cr_img *img, void **pobj, int type, bool global_info
        , bool eof) {

	char img_name_buf[PATH_MAX];
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size;
	int ret = -1;
    ProtobufCAllocator *allocator = NULL;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d on %s\n", type, image_name(img, img_name_buf));
		return -1;
	}

	*pobj = NULL;

    if (global_info) {
        allocator = xmalloc (sizeof(*allocator));
        if (!allocator)
            goto err;
        allocator->alloc = fshmalloc_proto;
        allocator->free = fshfree_last_proto;
        allocator->allocator_data = NULL;
    }

	if (unlikely(empty_image(img)))
		ret = 0;
	else
		ret = bread(&img->_x, &size, sizeof(size));

	if (ret == 0) {

        xfree (allocator);
        allocator = NULL;
		if (eof) {
			return 0;
		} else {
			pr_err("Unexpected EOF on %s\n", image_name(img, img_name_buf));
			return -1;
		}

    } else if (ret < sizeof(size)) {

        pr_perror("Read %d bytes while %d expected on %s", ret, (int)sizeof(size),
			  image_name(img, img_name_buf));
        xfree (allocator);
        allocator = NULL;
		return -1;

    }

	if (size > sizeof(local)) {
		ret = -1;
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	ret = bread(&img->_x, buf, size);
	if (ret < 0) {
		pr_perror("Can't read %d bytes from file %s", size, image_name(img, img_name_buf));
		goto err;
	} else if (ret != size) {
		pr_perror("Read %d bytes while %d expected from %s", ret, size, image_name(img, img_name_buf));
		ret = -1;
		goto err;
	}

	*pobj = cr_pb_descs[type].unpack(allocator, size, buf);
	if (!*pobj) {
		ret = -1;
		pr_err("Failed unpacking object %p with size %d from %s\n", pobj, size, image_name(img, img_name_buf));
		goto err;
	}

	ret = 1;

err:
	if (buf != (void *)&local)
		xfree(buf);

    xfree (allocator);      // If arrived here due to error.
    allocator = NULL;
	return ret;

}

/*
 * Writes PB record (header + packed object pointed by @obj)
 * to file @fd, using @getpksize to get packed size and @pack
 * to implement packing
 *
 *  0 on success
 * -1 on error
 */
int pb_write_one_buf (struct cr_img *img, void *obj, int type, void *pbuf
        , u32 psize) {

	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size, packed;
	int ret = -1;
	struct iovec iov[2];
    struct xfer_metadata xfer_meta;

	if ((pbuf == NULL) && (!cr_pb_descs[type].pb_desc)) {
		pr_err("Wrong object requested %d\n", type);
		return -1;
	}

	if (lazy_image(img) && open_image_lazy(img))
		return -1;

    if (pbuf != NULL) {
        size = psize;
        buf = pbuf;
        goto skip_packing;
    }

	size = cr_pb_descs[type].getpksize(obj);
	if (size > (u32)sizeof(local)) {
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	packed = cr_pb_descs[type].pack(obj, buf);
	if (packed != size) {
		pr_err("Failed packing PB object %p\n", obj);
		goto err;
	}

skip_packing:
	iov[0].iov_base = &size;
	iov[0].iov_len = sizeof(size);
	iov[1].iov_base = buf;
	iov[1].iov_len = size;

    // Send all dumps to xfer-server except "stats.img"
    if (!(opts.use_xfer_server) || (type == PB_STATS))
        goto save_local;

    xfer_meta.type = img->ftype;
    xfer_meta.size = size;
    xfer_meta.save_method = PB_IMG_BUF;
    snprintf(xfer_meta.img_name, NAME_MAX, "%s", img->name);
	pr_debug ("xfer-server: Sending %s (%d) to destination.\n", xfer_meta.img_name, xfer_meta.type);
	mutex_lock (xfer_client_send_lock);
    ret = send_to_xfer_server_buf (&xfer_meta, buf);
	mutex_unlock (xfer_client_send_lock);
    if (ret < 0) {
	pr_perror ("Error in sending %s (%d) to destination.\n", xfer_meta.img_name, xfer_meta.type);
        goto err;
    }

    // XXX: Shiv
    // Save dump file locally if it is "PB_INVENTORY" type because it is
    // required to detect pid reuse while page dumping.
    //
    // TODO:
    // Check whether sending "inventory.img" file to xfer-server is required at
    // all or not ??
    //
    if (type != PB_INVENTORY)
        goto out;

save_local:
    ret = bwritev(&img->_x, iov, 2);
    if (ret != size + sizeof(size)) {
        pr_perror("Can't write %d bytes", (int)(size + sizeof(size)));
        goto err;
    }

out:
	ret = 0;

err:
	if (buf != (void *)&local)
		xfree(buf);
	return ret;

}

static inline void free_msg (ProtobufCMessage *msg
        , struct collect_image_info *cinfo) {

    ProtobufCAllocator allocator, *alloc_ptr = NULL;

    if (cinfo->info_type == PRST_INFO_GLOBAL) {
        allocator.alloc = fshmalloc_proto;
        allocator.free = fshfree_last_proto;
        allocator.allocator_data = NULL;
        alloc_ptr = &allocator;
    }

    cr_pb_descs[cinfo->pb_type].free(msg, alloc_ptr);

}

int collect_entry (ProtobufCMessage *msg, struct collect_image_info *cinfo) {

	void *obj;
	void *(*o_alloc)(size_t size) = malloc;
	void (*o_free)(void *ptr) = free;

	if (cinfo->flags & COLLECT_SHARED) {
		o_alloc = fshmalloc;
		o_free = fshfree_last;
	}

    // You also need shared memory space for all global info which are processed
    // by other processes in parallel restore.
    if (cinfo->info_type == PRST_INFO_GLOBAL) {
        o_alloc = fshmalloc;
        o_free = fshfree_last;
    }

	if (cinfo->priv_size) {
		obj = o_alloc(cinfo->priv_size);
		if (!obj)
			return -1;
	} else
		obj = NULL;

    // First search whether info is already processed in previous iteration.
    if (cinfo->search_and_update(msg)) {
        cinfo->flags |= COLLECT_HAPPENED;
        o_free (obj);
        //free_msg (msg, cinfo);
        goto skip_collect;
    }

    // Not found, so collect and add it to respective list.
	cinfo->flags |= COLLECT_HAPPENED;
	if (cinfo->collect(obj, msg, NULL) < 0) {
		o_free(obj);
		return -1;
	}

skip_collect:
	return 0;

}

int collect_image (struct collect_image_info *cinfo) {

	int ret;
    bool global_info = false;
	struct cr_img *img;
	void *(*o_alloc)(size_t size) = malloc;
	void (*o_free)(void *ptr) = free;

	pr_info("Collecting %d/%d (flags %x)\n", cinfo->fd_type, cinfo->pb_type, cinfo->flags);

	img = open_image(cinfo->fd_type, O_RSTR);
	if (!img)
		return -1;

	if (cinfo->flags & COLLECT_SHARED) {
		o_alloc = fshmalloc;
		o_free = fshfree_last;
	}

    // You also need shared memory space for all global info which are processed
    // by other processes in parallel restore.
    if (cinfo->info_type == PRST_INFO_GLOBAL) {
        global_info = true;
        o_alloc = fshmalloc;
        o_free = fshfree_last;
    }

	while (1) {
		void *obj;
		ProtobufCMessage *msg;

		if (cinfo->priv_size) {
			ret = -1;
			obj = o_alloc(cinfo->priv_size);
			if (!obj)
				break;
		} else
			obj = NULL;

		ret = pb_read_one_eof(img, &msg, cinfo->pb_type, global_info);
		if (ret <= 0) {
			o_free(obj);
			break;
		}

        // First search whether info is already processed in previous iteration.
        if (cinfo->search_and_update(msg)) {
            cinfo->flags |= COLLECT_HAPPENED;
            o_free (obj);
            //free_msg (msg, cinfo);
            goto skip_collect;
        }

        // Not found, so collect and add it to respective list.
		cinfo->flags |= COLLECT_HAPPENED;
		ret = cinfo->collect(obj, msg, img);
		if (ret < 0) {
			o_free(obj);
            free_msg (msg, cinfo);
			break;
		}

skip_collect:
		if (!cinfo->priv_size && !global_info && !(cinfo->flags & COLLECT_NOFREE))
            free_msg (msg, cinfo);

	}

	close_image(img);
	pr_debug(" `- ... done\n");
	return ret;

}
