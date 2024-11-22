#ifndef __CR_RST_FMALLOC__H__
#define __CR_RST_FMALLOC__H__

#include "common/lock.h"

/*
 * Approach:
 *
 * Some data structures are created by CRIU process (in the processing of
 * pstree, files and other global info) as shared that are used by the processes
 * created by the CRIU to do per process processing. Now in case of iterative
 * restore, if some addition happened then we can not refelect those because
 * processes are already forked. In that case we need to have a big shared
 * region which can handle additions upto some limit. This way even forked
 * processes will have those additions in successive iterations, if any.
 *
 * We don't need to free arbitrary object, thus allocation is simple (linear)
 * and only the last object can be freed (pop-ed from buffer).
 */

struct rst_fixed_shmem {
    void *init_addr, *start_addr, *free_addr;
    unsigned long total_size;
    unsigned long free_bytes;
    mutex_t lock;
};


/**
 * External apis
 */
extern void *fshmalloc (size_t bytes);
extern void *fshmalloc_proto (void *data, size_t bytes);
extern int fshmem_init (void);
extern int fshmem_unmap (void);
extern void fshfree_last (void *ptr);
extern void fshfree_last_proto (void *data, void *ptr);
extern unsigned long fsh_get_used_bytes (void);

#endif /* __CR_RST_FMALLOC__H__ */
