#ifndef __CR_FIFO_H__
#define __CR_FIFO_H__

struct fd_parms;
struct cr_imgset;

extern const struct fdtype_ops fifo_dump_ops;
extern struct collect_image_info fifo_cinfo;
extern struct collect_image_info fifo_data_cinfo;

extern int fifo_head_shalloc (void);
extern int pd_hash_fifo_shalloc (void);

#endif /* __CR_FIFO_H__ */
