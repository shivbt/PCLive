#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "page.h"
#include "rst-fmalloc.h"
#include "log.h"
#include "common/bug.h"

static struct rst_fixed_shmem *rst_fshmem = NULL;

/**
 * Helper function to allocate shared memory region of 1GB.
 * Returns:
 *      -1: In case of any error
 *      0:  In case of success
 */
static inline int rst_fixed_shmem_init (void) {

    void *addr;
    int size;
    int meta_size;

    //
    // Allocate 1GB shared memory region.
    //
    // XXX: Shiv
    // 1GB is the max limit linux kernel can give to an application. I have
    // tested it with 2 GB but it is failing. Although to allocate 2GB memory,
    // we can call 2 mmaps with 1GB and MAP_FIXED flag (will look into this later).
    //
    size = 256 * 1024 * page_size();                // 1GB if page_size is 4KB
    addr = mmap (NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    if (addr == MAP_FAILED)
        return -1;

    pr_debug ("Fixed shared memory region created from %p (+1GB)\n", addr);
    meta_size = sizeof (*rst_fshmem);
    rst_fshmem = addr;
    rst_fshmem->init_addr = addr;
    rst_fshmem->total_size = size;
    addr = addr + meta_size;
    rst_fshmem->start_addr = addr;
    rst_fshmem->free_addr = addr;
    rst_fshmem->free_bytes = size - meta_size;

    mutex_init (&rst_fshmem->lock);

    // Simple return
    return 0;

}

/**
 * External function to be called for the allocation of 1GB shared memory chunk.
 * Returns:
 *      -1: In case of any error
 *      0:  In case of success
 */
int fshmem_init (void) {

    if (rst_fixed_shmem_init ()) {
        pr_perror ("Unable to create large shared memory chunk\n");
        return -1;
    }
    return 0;

}

/**
 * External function to be called for the unmapping of 1GB shared memory chunk.
 * Returns:
 *      -1: In case of any error
 *      0:  In case of success
 */
int fshmem_unmap (void) {

    if (munmap (rst_fshmem->init_addr, rst_fshmem->total_size)) {
        pr_perror ("Unable to unmap fixed shared chunk %p (%lx)"
                , rst_fshmem->init_addr, rst_fshmem->total_size);
        return -1;
    }
    rst_fshmem = NULL;
    pr_debug ("Fixed shared memory region is freed\n");
    return 0;

}

/**
 * Word-align the current freelist pointer for the next allocation. If we don't
 * align pointers, some futex and atomic operations can fail.
 */
static inline void rst_fixed_shmem_align (void) {

    void *ptr;
    ptr = (void *) round_up ((unsigned long)rst_fshmem->free_addr, sizeof(void *));
    rst_fshmem->free_bytes -= (ptr - rst_fshmem->free_addr);
    rst_fshmem->free_addr = ptr;

}

/**
 * Function to get the a shared memory chunk from the allocated big shared
 * memory region.
 *
 * XXX: Idea
 *
 * Embed size along with the data as shown below:
 * ..|..size..|............data.............|
 *
 * Returns:
 *      pointer:    If allocation is successfull
 *      null:       If allocation is not possible
 *
 */
static void *rst_fshmem_alloc (unsigned long size) {

    void *data_addr;
    unsigned long *size_addr;
    unsigned long embedded_meta_size, total_size;

    if (rst_fshmem->free_bytes < size) {
        pr_perror ("Shared memory limit (1GB) is reached, can't allocate more.\n");
        return NULL;
    }

    embedded_meta_size = sizeof (unsigned long);
    total_size = size + embedded_meta_size;
    data_addr = rst_fshmem->free_addr;
    size_addr = (unsigned long *) data_addr;
    *size_addr = size;                      // Size is embedded.
    data_addr += embedded_meta_size;        // Pointer is adjusted to store data.
    rst_fshmem->free_addr += total_size;
    rst_fshmem->free_bytes -= total_size;

    // Return the pointer which points to the start of the data part.
    return data_addr;

}

/**
 * Function to reclaim the last allocated shared memory chunk from the
 * allocated big shared memory region.
 *
 * XXX: Idea
 *
 * Extract the size from the given data pointer and reclaim the space by
 * considering below layout:
 *
 * ..|..size..|............data.............|
 *
 */
static void rst_fixed_shmem_free_last (void *ptr) {

    unsigned long *size_addr;
    unsigned long size, embedded_meta_size;
    unsigned long reclaimed_size;

    // Silent check for passed pointer.
    if (!ptr || (ptr < rst_fshmem->start_addr))
        return;

    // Extract the size from the given pointer.
    embedded_meta_size = sizeof (unsigned long);

    // Silent return if not valid pointer for free call.
    if ((ptr - embedded_meta_size) < rst_fshmem->start_addr)
        return;

    // Get the size.
    size_addr = (unsigned long *) (ptr - embedded_meta_size);
    size = *size_addr;
    reclaimed_size = size + embedded_meta_size;

    // Now reclaim the last allocated chunk, if allowed according to our
    // linear allocation and free strategy.
    if ((ptr + size) == rst_fshmem->free_addr) {
        rst_fshmem->free_addr -= reclaimed_size;
        rst_fshmem->free_bytes += reclaimed_size;
    }

}

/**
 * External function to get the a shared memory chunk from the allocated
 * big shared memory region.
 */
void *fshmalloc (size_t bytes) {
    void *addr = NULL;
    mutex_lock (&rst_fshmem->lock);
    rst_fixed_shmem_align ();
    addr = rst_fshmem_alloc (bytes);
    mutex_unlock (&rst_fshmem->lock);
    return addr;
}

/**
 * External function to get the a shared memory chunk from the allocated
 * big shared memory region.
 */
unsigned long fsh_get_used_bytes (void) {
    unsigned long used_bytes;
    mutex_lock (&rst_fshmem->lock);
    used_bytes = rst_fshmem->total_size - rst_fshmem->free_bytes;
    mutex_unlock (&rst_fshmem->lock);
    return used_bytes;
}

/**
 * External function to get the a shared memory chunk from the allocated
 * big shared memory region for protobuf.
 */
void *fshmalloc_proto (void *data, size_t bytes) {
    return fshmalloc (bytes);
}

/* External function to free the last allocated chunk */
void fshfree_last (void *ptr) {
    mutex_lock (&rst_fshmem->lock);
    rst_fixed_shmem_free_last (ptr);
    mutex_unlock (&rst_fshmem->lock);
    return;
}

/* External function to free the last allocated chunk for protobuf*/
void fshfree_last_proto (void *data, void *ptr) {
    fshfree_last (ptr);
}
