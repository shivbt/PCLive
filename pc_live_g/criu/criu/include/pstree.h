#ifndef __CR_PSTREE_H__
#define __CR_PSTREE_H__

#include "common/list.h"
#include "common/lock.h"
#include "pid.h"
#include "xmalloc.h"
#include "images/core.pb-c.h"

/*
 * That's the init process which usually inherit
 * all orphaned children in the system.
 */
#define INIT_PID (1)

// To make threads as linked list instead of array.
struct pstree_item_thread {
    struct pid thread;
    struct list_head thread_list;
};

// To store free pstree item of current iteration which can be
// reused in the next iteration in case of iterative migration.
struct free_pstree_item {
    unsigned long item_address;
    struct list_head free_item_list;
};

struct prst_message {
    uint32_t cmd;       // Command
    int ret_code;       // Return code response from the task.
    futex_t ack;        // Completion indicator
};

struct pstree_item {

    struct pstree_item *parent;
	struct list_head children;                  // list of my children
	struct list_head sibling;                   // linkage in my parent's children list

	struct pid *pid;
	pid_t pgid;
	pid_t sid;
	pid_t born_sid;

	int nr_threads;                             // number of threads
	//struct pid *threads;                      // array of threads
    struct list_head threads;                   // Linked list of threads.
    futex_t notif;                              // Used to communicate among pCRIU, root and other processes for global update
    futex_t mem_notif;                          // Used to communicate among pCRIU, container processes for mem update
    futex_t xfer_complete;                      // Used to communicate among pCRIU, container processes for pages transfer completion
    struct prst_message prst_msg;               // Used to communicate among pCRIU, root and other processes
    bool task_created;                          // Indicate that the task is already forked.
    bool task_updated;                          // Indicate that the task is already forked.
    int curr_iter;                              // Current iteration for this process.
    int glob_iter;                              // Global iteration for the container/ pstree.
    bool is_last_iter;                          // Indicate whether it is last iteration.

	CoreEntry **core;
	TaskKobjIdsEntry *ids;
	union {
		futex_t task_st;
		unsigned long task_st_le_bits;
	};

};

static inline pid_t vpid(const struct pstree_item *i)
{
	return i->pid->ns[0].virt;
}

enum {
	FDS_EVENT_BIT = 0,
};
#define FDS_EVENT (1 << FDS_EVENT_BIT)

extern struct pstree_item *current;

struct rst_info;
/* See alloc_pstree_item() for details */
static inline struct rst_info *rsti(struct pstree_item *i)
{
	return (struct rst_info *)(i + 1);
}

struct thread_lsm {
	char *profile;
	char *sockcreate;
};

struct ns_id;
struct dmp_info {
	struct ns_id *netns;
	struct page_pipe *mem_pp;
	struct parasite_ctl *parasite_ctl;
	struct parasite_thread_ctl **thread_ctls;
	uint64_t *thread_sp;

	/*
	 * Although we don't support dumping different struct creds in general,
	 * we do for threads. Let's keep track of their profiles here; a NULL
	 * entry means there was no LSM profile for this thread.
	 */
	struct thread_lsm **thread_lsms;
};

static inline struct dmp_info *dmpi(const struct pstree_item *i)
{
	return (struct dmp_info *)(i + 1);
}

/* ids is allocated and initialized for all alive tasks */
static inline int shared_fdtable(struct pstree_item *item)
{
	return (item->parent && item->ids->files_id == item->parent->ids->files_id);
}

static inline bool is_alive_state(int state)
{
	return (state == TASK_ALIVE) || (state == TASK_STOPPED);
}

static inline bool task_alive (struct pstree_item *i) {
    return ((!i->pid->is_deleted) && is_alive_state(i->pid->state));
}

extern void free_pstree(struct pstree_item *root_item);
extern struct pstree_item *__alloc_pstree_item(bool rst);
#define alloc_pstree_item() __alloc_pstree_item(false)
extern int init_pstree_helper(struct pstree_item *ret);

extern struct pstree_item *lookup_create_item(pid_t pid);
extern void pstree_insert_pid(struct pid *pid_node);
extern void pstree_insert_pid_thread (struct pstree_item *item, struct pid *pid_node);
extern int init_pid_root_rb (bool is_restore);
extern struct pid *pstree_pid_by_virt(pid_t pid);
extern struct pstree_item_thread *create_thread_item (struct pstree_item *item, pid_t vpid, bool rst);

extern struct pstree_item *root_item;
extern struct pstree_item *pstree_item_next(struct pstree_item *item);
#define for_each_pstree_item(pi) for (pi = root_item; pi != NULL; pi = pstree_item_next(pi))
#define for_each_pstree_item_current(item, pi) for (pi = item; pi != NULL; pi = pstree_item_next(pi))

extern bool restore_before_setsid(struct pstree_item *child);
extern int prepare_pstree (bool init);
extern int prepare_dummy_pstree(void);

extern int dump_pstree(struct pstree_item *root_item);

struct pstree_item *pstree_item_by_real(pid_t virt);
struct pstree_item *pstree_item_by_virt(pid_t virt);

extern int pid_to_virt(pid_t pid);

// Added by Shiv
struct pstree_item *get_pstree_item_virt_iter (int virt_pid);

struct task_entries;
extern struct task_entries *task_entries;
extern int prepare_task_entries(void);
extern void clean_pstree (bool is_last_iter);
extern int prepare_dummy_task_state(struct pstree_item *pi);

extern int get_task_ids(struct pstree_item *);
extern TaskKobjIdsEntry *root_ids;

extern void core_entry_free(CoreEntry *core);
extern CoreEntry *core_entry_alloc(int alloc_thread_info, int alloc_tc);
extern int pstree_alloc_cores(struct pstree_item *item);
extern void pstree_free_cores(struct pstree_item *item);

extern int collect_pstree_ids(void);

extern int preorder_pstree_traversal(struct pstree_item *item, int (*f)(struct pstree_item *));
#endif /* __CR_PSTREE_H__ */
