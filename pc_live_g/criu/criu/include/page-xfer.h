#ifndef __CR_PAGE_XFER__H__
#define __CR_PAGE_XFER__H__
#include "pagemap.h"

#define CR_IMG_BUF      1       /** Different save methods....*/
#define PB_IMG_BUF      2
#define CR_IMG_RAW      3

struct ps_info {
	int pid;
	unsigned short port;
};

extern int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd);

extern int cr_xfer_server (void);

struct xfer_metadata {
    int type;
    u32 size;
    u64 dst_id;
    short save_method;
    char img_name [NAME_MAX];
};
extern int send_to_xfer_server_buf (struct xfer_metadata *xfer_meta, const void *buf);
extern int send_to_xfer_server_fd (struct xfer_metadata *xfer_meta, int fd);

extern int init_page_transfer_xfer_server (void);

extern int do_send_metadata_xfer_server (struct xfer_metadata *meta);

/* User buffer for read-mode pre-dump*/
#define BUFFER_SIZE (PIPE_MAX_SIZE << PAGE_SHIFT)

/*
 * page_xfer -- transfer pages into image file.
 * Two images backends are implemented -- local image file
 * and page-server image file.
 */

struct page_xfer {
	/* transfers one vaddr:len entry */
	int (*write_pagemap)(struct page_xfer *self, struct iovec *iov, u32 flags);
	/* transfers pages related to previous pagemap */
	int (*write_pages)(struct page_xfer *self, int pipe, unsigned long len);
	void (*close)(struct page_xfer *self);

	/*
	 * In case we need to dump pagemaps not as-is, but
	 * relative to some address. Used, e.g. by shmem.
	 */
	unsigned long offset;
	bool transfer_lazy;

    int virt_pid;

	/* private data for every page-xfer engine */
	union {
		struct /* local */ {
			struct cr_img *pmi; /* pagemaps */
			struct cr_img *pi; /* pages */
		};

		struct /* page-server */ {
			int sk;
			u64 dst_id;
		};
	};

	struct page_read *parent;
};

extern int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long id);
struct page_pipe;
extern int page_xfer_dump_pages(struct page_xfer *, struct page_pipe *);
extern int page_xfer_predump_pages(int pid, struct page_xfer *, struct page_pipe *);
extern int connect_to_xfer_server_to_send(void);
extern int send_runc_descriptors_file_xfer_server(void);
extern int connect_to_page_server_to_recv(int epfd);
extern int disconnect_from_page_server(void);

extern int disconnect_from_xfer_server (void);
extern int send_last_page_iov_cmd_xfer (void);
extern int check_parent_page_xfer(int fd_type, unsigned long id);

/*
 * The post-copy migration makes it necessary to receive pages from
 * remote dump. The protocol we use for that is quite simple:
 * - lazy-pages sends request containing PS_IOV_GET(nr_pages, vaddr, pid)
 * - dump-side page server responds with PS_IOV_ADD(nr_pages, vaddr,
     pid) or PS_IOV_ADD(0, 0, 0) if it failed to locate the required
     pages
 * - dump-side page server sends the raw page data
 */

/* async request/receive of remote pages */
extern int request_remote_pages(unsigned long img_id, unsigned long addr, int nr_pages);

typedef int (*ps_async_read_complete)(unsigned long img_id, unsigned long vaddr, int nr_pages, void *);
extern int page_server_start_read(void *buf, int nr_pages, ps_async_read_complete complete, void *priv, unsigned flags);

#endif /* __CR_PAGE_XFER__H__ */
