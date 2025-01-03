#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>

#include "types.h"
#include "cr_options.h"
#include "pstree.h"
#include "rst-fmalloc.h"
#include "common/lock.h"
#include "namespaces.h"
#include "files.h"
#include "tty.h"
#include "mount.h"
#include "dump.h"
#include "util.h"
#include "net.h"

#include "protobuf.h"
#include "images/pstree.pb-c.h"
#include "crtools.h"

struct pstree_item *root_item = NULL;   // NULL is assigned by Shiv
struct rb_root *pid_root_rb = NULL;     // NULL is assigned by Shiv
static struct rb_root pid_root_rb_dump; // Used for dump only. Restore will use above.

static LIST_HEAD (free_pstree_items);

void core_entry_free(CoreEntry *core)
{
	if (core->tc && core->tc->timers)
		xfree(core->tc->timers->posix);
	if (core->thread_core)
		xfree(core->thread_core->creds->groups);
	arch_free_thread_info(core);
	xfree(core);
}

#ifndef RLIM_NLIMITS
#define RLIM_NLIMITS 16
#endif

CoreEntry *core_entry_alloc(int th, int tsk)
{
	size_t sz;
	CoreEntry *core = NULL;
	void *m;

	sz = sizeof(CoreEntry);
	if (tsk) {
		sz += sizeof(TaskCoreEntry) + TASK_COMM_LEN;
		if (th) {
			sz += sizeof(TaskRlimitsEntry);
			sz += RLIM_NLIMITS * sizeof(RlimitEntry *);
			sz += RLIM_NLIMITS * sizeof(RlimitEntry);
			sz += sizeof(TaskTimersEntry);
			sz += 3 * sizeof(ItimerEntry); /* 3 for real, virt and prof */
		}
	}
	if (th) {
		CredsEntry *ce = NULL;

		sz += sizeof(ThreadCoreEntry) + sizeof(ThreadSasEntry) + sizeof(CredsEntry);

		sz += CR_CAP_SIZE * sizeof(ce->cap_inh[0]);
		sz += CR_CAP_SIZE * sizeof(ce->cap_prm[0]);
		sz += CR_CAP_SIZE * sizeof(ce->cap_eff[0]);
		sz += CR_CAP_SIZE * sizeof(ce->cap_bnd[0]);
		/*
		 * @groups are dynamic and allocated
		 * on demand.
		 */
	}

	m = xmalloc(sz);
	if (m) {
		core = xptr_pull(&m, CoreEntry);
		core_entry__init(core);
		core->mtype = CORE_ENTRY__MARCH;

		if (tsk) {
			core->tc = xptr_pull(&m, TaskCoreEntry);
			task_core_entry__init(core->tc);
			core->tc->comm = xptr_pull_s(&m, TASK_COMM_LEN);
			memzero(core->tc->comm, TASK_COMM_LEN);

			if (th) {
				TaskRlimitsEntry *rls;
				TaskTimersEntry *tte;
				int i;

				rls = core->tc->rlimits = xptr_pull(&m, TaskRlimitsEntry);
				task_rlimits_entry__init(rls);

				rls->n_rlimits = RLIM_NLIMITS;
				rls->rlimits = xptr_pull_s(&m, sizeof(RlimitEntry *) * RLIM_NLIMITS);

				for (i = 0; i < RLIM_NLIMITS; i++) {
					rls->rlimits[i] = xptr_pull(&m, RlimitEntry);
					rlimit_entry__init(rls->rlimits[i]);
				}

				tte = core->tc->timers = xptr_pull(&m, TaskTimersEntry);
				task_timers_entry__init(tte);
				tte->real = xptr_pull(&m, ItimerEntry);
				itimer_entry__init(tte->real);
				tte->virt = xptr_pull(&m, ItimerEntry);
				itimer_entry__init(tte->virt);
				tte->prof = xptr_pull(&m, ItimerEntry);
				itimer_entry__init(tte->prof);
			}
		}

		if (th) {
			CredsEntry *ce;

			core->thread_core = xptr_pull(&m, ThreadCoreEntry);
			thread_core_entry__init(core->thread_core);
			core->thread_core->sas = xptr_pull(&m, ThreadSasEntry);
			thread_sas_entry__init(core->thread_core->sas);
			ce = core->thread_core->creds = xptr_pull(&m, CredsEntry);
			creds_entry__init(ce);

			ce->n_cap_inh = CR_CAP_SIZE;
			ce->n_cap_prm = CR_CAP_SIZE;
			ce->n_cap_eff = CR_CAP_SIZE;
			ce->n_cap_bnd = CR_CAP_SIZE;
			ce->cap_inh = xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_inh[0]));
			ce->cap_prm = xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_prm[0]));
			ce->cap_eff = xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_eff[0]));
			ce->cap_bnd = xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_bnd[0]));

			if (arch_alloc_thread_info(core)) {
				xfree(core);
				core = NULL;
			}
		}
	}

	return core;
}

int pstree_alloc_cores (struct pstree_item *item) {

    struct pstree_item_thread *thread_item;
	unsigned int i;

	item->core = xzalloc(sizeof(*item->core) * item->nr_threads);
	if (!item->core)
		return -1;

	//for (i = 0; i < item->nr_threads; i++) {
    i = 0;
    list_for_each_entry(thread_item, &(item->threads), thread_list) {

		//if (item->threads[i].real == item->pid->real)
		if (thread_item->thread.real == item->pid->real)
			item->core[i] = core_entry_alloc(1, 1);
		else
			item->core[i] = core_entry_alloc(1, 0);

		if (!item->core[i])
			goto err;

        i++;

	}

	return 0;

err:
	pstree_free_cores(item);
	return -1;

}

void pstree_free_cores(struct pstree_item *item)
{
	unsigned int i;

	if (item->core) {
		for (i = 1; i < item->nr_threads; i++)
			if (item->core[i])
				core_entry_free(item->core[i]);
		xfree(item->core);
		item->core = NULL;
	}
}

/**
 * Function to free allocated linked list of threads.
 */
static inline void free_threads (struct pstree_item *item, bool is_prestore) {

    struct pstree_item_thread *thread;

    while (!list_empty(&item->threads)) {
        thread = list_first_entry(&(item->threads), struct pstree_item_thread, thread_list);
        list_del(&thread->thread_list);
        if (is_prestore)
            fshfree_last (thread);
        else
            xfree (thread);
    }

}

/**
 * Function to make a pstree item as reusable such that it can be used in
 * next iteration (and we don't need any mem allocation system call)
 */
static inline void make_pstree_item_reusable (struct pstree_item *item) {

    struct free_pstree_item *free_item = NULL;
    free_item = xmalloc (sizeof(*free_item));
    if (!free_item) {
        pr_warn ("Not able to add pstree item (%d) in reusable list\n", item->pid->ns[0].virt);
        return;
    }
    free_item->item_address = (unsigned long) item;
    list_add_tail (&free_item->free_item_list, &free_pstree_items);
    rb_erase (&item->pid->ns[0].node, pid_root_rb);

}

/**
 * Function to free one pstree item and make it reusable, if necessary.
 */
static inline void free_one_pstree_item (struct pstree_item *item
        , bool reusable, bool is_prestore) {

    list_del(&item->sibling);

    if (!is_prestore) {
        pstree_free_cores(item);
    }

    free_threads(item, is_prestore);
    if (item->ids) {
        if (is_prestore)
            fshfree_last (item->ids);
        else
            xfree (item->ids);
        item->ids = NULL;
    }

    // Check if this pstree item can be reused in future iteration.
    if (reusable) {
        make_pstree_item_reusable (item);
    } else {
        if (is_prestore)
            fshfree_last (item);
        else
            xfree (item);
        item = NULL;
    }

}

void free_pstree (struct pstree_item *root_item) {

	struct pstree_item *item = root_item, *parent;

	while (item) {
		if (!list_empty(&item->children)) {
			item = list_first_entry(&item->children, struct pstree_item, sibling);
			continue;
		}
		parent = item->parent;
		free_one_pstree_item (item, false, false);
		item = parent;
    }

}

/**
 * Function to create a thread item and insert it into the item list.
 */
struct pstree_item_thread *create_thread_item (struct pstree_item *item
        , pid_t vpid, bool rst) {

    struct pstree_item_thread *thread_item;

    if (rst) {
        thread_item = fshmalloc (sizeof(struct pstree_item_thread));
    } else {
        thread_item = xzalloc (sizeof(struct pstree_item_thread));
    }
    if (!thread_item)
        return NULL;

    INIT_LIST_HEAD (&thread_item->thread_list);
    thread_item->thread.real = -1;
    thread_item->thread.ns[0].virt = vpid;
    thread_item->thread.state = TASK_THREAD;
    thread_item->thread.item = NULL;
    thread_item->thread.is_deleted = false;

    // Insert it in the thread list.
    list_add_tail (&thread_item->thread_list, &item->threads);

    return thread_item;

}

/**
 * Function to get either new or reused (from prev iteration) pstree item.
 */
struct pstree_item *get_pstree_item (int size) {

    struct pstree_item *item = NULL;
    struct free_pstree_item *free_item;

    // First try to get it from reusable pstree item.
    if (!list_empty(&free_pstree_items)) {
        free_item = list_first_entry(&free_pstree_items, struct free_pstree_item, free_item_list);
        list_del(&free_item->free_item_list);
        item = (struct pstree_item *) free_item->item_address;
        xfree(free_item);
    } else {
        item = fshmalloc (size);
    }

    // And now return the item.
    return item;

}

/**
 * Function to allocate space for the root node of rb tree to store pid values
 * of pstree which can be searched faster.
 */
int init_pid_root_rb (bool is_restore) {

    int sz = sizeof (*pid_root_rb);

    if (!is_restore) {
        pid_root_rb = &pid_root_rb_dump;
        return 0;
    }

    pid_root_rb = fshmalloc (sz);
    if (pid_root_rb == NULL) {
        pr_perror ("Can't allocate more shared space\n");
        return 1;
    }
    memset (pid_root_rb, 0, sz);
    return 0;

}

struct pstree_item *__alloc_pstree_item (bool rst) {

	struct pstree_item *item;
	int sz;

	if (!rst) {

		sz = sizeof(*item) + sizeof(struct dmp_info) + sizeof(struct pid);
		item = xzalloc(sz);
		if (!item)
			return NULL;
		item->pid = (void *)item + sizeof(*item) + sizeof(struct dmp_info);

    } else {

        sz = sizeof(*item) + sizeof(struct rst_info) + sizeof(struct pid);
		//item = shmalloc(sz);
        item = get_pstree_item (sz);
		if (!item)
			return NULL;

		memset(item, 0, sz);
		vm_area_list_init(&rsti(item)->vmas);
		INIT_LIST_HEAD(&rsti(item)->vma_io);
		item->pid = (void *)item + sizeof(*item) + sizeof(struct rst_info);

    }

	INIT_LIST_HEAD(&item->children);
	INIT_LIST_HEAD(&item->sibling);

	item->pid->ns[0].virt = -1;
	item->pid->real = -1;
	item->pid->state = TASK_UNDEF;
	item->born_sid = -1;
	item->pid->item = item;
    item->pid->is_deleted = false;      // Added by Shiv for iterative parallel-restore.
    if (rst) {
        item->nr_threads = 1;           // Added by Shiv for iterative parallel-restore.
    }
    INIT_LIST_HEAD (&item->threads);    // Added by Shiv for iterative parallel-restore.
    item->parent = NULL;                // Added by Shiv for iterative parallel-restore.
	futex_init(&item->task_st);
    futex_init(&item->notif);           // Added by Shiv for iterative parallel-restore.
    item->task_created = false;         // Added by Shiv for iterative parallel-restore.
    item->task_updated = false;         // Added by Shiv for iterative parallel-restore.
    item->curr_iter = 1;                // Added by Shiv for iterative parallel-restore.
    item->glob_iter = 1;                // Added by Shiv for iterative parallel-restore.
    item->is_last_iter = ((opts.no_prestore) || (opts.rp == opts.iterations)) ? true : false;

	return item;

}

int init_pstree_helper(struct pstree_item *ret)
{
	BUG_ON(!ret->parent);
	ret->pid->state = TASK_HELPER;
	rsti(ret)->clone_flags = CLONE_FILES | CLONE_FS;
	if (shared_fdt_prepare(ret) < 0)
		return -1;
	task_entries->nr_helpers++;
	return 0;
}

/* Deep first search on children */
struct pstree_item *pstree_item_next(struct pstree_item *item)
{
	if (!list_empty(&item->children))
		return list_first_entry(&item->children, struct pstree_item, sibling);

	while (item->parent) {
		if (item->sibling.next != &item->parent->children)
			return list_entry(item->sibling.next, struct pstree_item, sibling);
		item = item->parent;
	}

	return NULL;
}

/* Preorder traversal of pstree item */
int preorder_pstree_traversal(struct pstree_item *item, int (*f)(struct pstree_item *))
{
	struct pstree_item *cursor;

	if (f(item) < 0)
		return -1;

	list_for_each_entry(cursor, &item->children, sibling) {
		if (preorder_pstree_traversal(cursor, f) < 0)
			return -1;
	}

	return 0;
}

int dump_pstree (struct pstree_item *root_item) {

	struct pstree_item *item = root_item;
    struct pstree_item_thread *thread_item;
	PstreeEntry e = PSTREE_ENTRY__INIT;
	int ret = -1, i;
	struct cr_img *img;

	pr_info("\n");
	pr_info("Dumping pstree (pid: %d)\n", root_item->pid->real);
	pr_info("----------------------------------------\n");

	/*
	 * Make sure we're dumping session leader, if not an
	 * appropriate option must be passed.
	 *
	 * Also note that if we're not a session leader we
	 * can't get the situation where the leader sits somewhere
	 * deeper in process tree, thus top-level checking for
	 * leader is enough.
	 */
	if (vpid(root_item) != root_item->sid) {
		if (!opts.shell_job) {
			pr_err("The root process %d is not a session leader. "
			       "Consider using --" OPT_SHELL_JOB " option\n",
			       vpid(item));
			return -1;
		}
	}

	img = open_image(CR_FD_PSTREE, O_DUMP);
	if (!img)
		return -1;

	for_each_pstree_item(item) {

        pr_info("Process: %d(%d)\n", vpid(item), item->pid->real);

		e.pid = vpid(item);

        // XXX: Shiv
        //
        // The leader thread's vtid should be same as vpid of the task.
        // Doing this here to make sure that pstree can be dumped (in pre-dump)
        // without going through the code path of core-dump like dump.
        // I am not planning to dump cores during pre-dump rounds.
        thread_item = list_first_entry(&(item->threads), struct pstree_item_thread, thread_list);
        thread_item->thread.ns[0].virt = vpid (item);

		e.ppid = item->parent ? vpid(item->parent) : 0;
		e.pgid = item->pgid;
		e.sid = item->sid;
		e.n_threads = item->nr_threads;

		e.threads = xmalloc(sizeof(e.threads[0]) * e.n_threads);
		if (!e.threads)
			goto err;

		//for (i = 0; i < item->nr_threads; i++)
        i = 0;
        list_for_each_entry(thread_item, &(item->threads), thread_list) {
            e.threads[i] = thread_item->thread.ns[0].virt;
            i++;
        }

		ret = pb_write_one(img, &e, PB_PSTREE);
		xfree(e.threads);

		if (ret)
			goto err;

	}
	ret = 0;

err:
	pr_info("----------------------------------------\n");
	close_image(img);
	return ret;

}

static int prepare_pstree_for_shell_job(pid_t pid)
{
	pid_t current_sid = getsid(pid);
	pid_t current_gid = getpgid(pid);

	struct pstree_item *pi;
	struct pid *tmp;

	pid_t old_sid;
	pid_t old_gid;

	if (!opts.shell_job)
		return 0;

	/* root_item is a session leader */
	if (root_item->sid == vpid(root_item))
		return 0;

	/*
	 * Migration of a root task group leader is a bit tricky.
	 * When a task yields SIGSTOP, the kernel notifies the parent
	 * with SIGCHLD. This means when task is running in a
	 * shell, the shell obtains SIGCHLD and sends a task to
	 * the background.
	 *
	 * The situation gets changed once we restore the
	 * program -- our tool become an additional stub between
	 * the restored program and the shell. So to be able to
	 * notify the shell with SIGCHLD from our restored
	 * program -- we make the root task to inherit the
	 * process group from us.
	 *
	 * Not that clever solution but at least it works.
	 */

	old_sid = root_item->sid;
	if (old_sid != current_sid) {
		pr_info("Migrating process tree (SID %d->%d)\n", old_sid, current_sid);

		tmp = pstree_pid_by_virt(current_sid);
		if (tmp) {
			pr_err("Current sid %d intersects with pid (%d) in images\n", current_sid, tmp->state);
			return -1;
		}

		for_each_pstree_item(pi) {
			if (pi->sid == old_sid)
				pi->sid = current_sid;
		}

		if (lookup_create_item(current_sid) == NULL)
			return -1;
	}

	/* root_item is a group leader */
	if (root_item->pgid == vpid(root_item))
		return 0;

	old_gid = root_item->pgid;
	if (old_gid != current_gid) {
		pr_info("Migrating process tree (GID %d->%d)\n", old_gid, current_gid);

		tmp = pstree_pid_by_virt(current_gid);
		if (tmp) {
			pr_err("Current gid %d intersects with pid (%d) in images\n", current_gid, tmp->state);
			return -1;
		}

		for_each_pstree_item(pi) {
			if (pi->pgid == old_gid)
				pi->pgid = current_gid;
		}

		if (lookup_create_item(current_gid) == NULL)
			return -1;
	}

	return 0;
}

/*
 * Try to find a pid node in the tree and insert a new one,
 * it is not there yet. If pid_node isn't set, pstree_item
 * is inserted.
 */
static struct pid *lookup_create_pid (pid_t pid, struct pid *pid_node) {

	struct rb_node *node = pid_root_rb->rb_node;
	struct rb_node **new = &(pid_root_rb->rb_node);
	struct rb_node *parent = NULL;

	while (node) {
		struct pid *this = rb_entry(node, struct pid, ns[0].node);

		parent = *new;
		if (pid < this->ns[0].virt)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (pid > this->ns[0].virt)
			node = node->rb_right, new = &((*new)->rb_right);
		else {
            this->is_deleted = false;
			return this;
        }
	}

	if (!pid_node) {
		struct pstree_item *item;

		item = __alloc_pstree_item(true);
		if (item == NULL)
			return NULL;

		item->pid->ns[0].virt = pid;
		pid_node = item->pid;
	}

    rb_link_and_balance(pid_root_rb, &pid_node->ns[0].node, parent, new);
    return pid_node;

}

/**
 * Try to find a pid node for a given thread id in the tree and insert a
 * new one, if it is not there yet.
 */
static struct pid *lookup_create_thread (struct pstree_item *item, pid_t pid
        , struct pid *pid_node, bool is_thread_leader, bool rst) {

    struct rb_node *node = pid_root_rb->rb_node;
    struct rb_node **new = &(pid_root_rb->rb_node);
    struct rb_node *parent = NULL;
    struct pstree_item_thread *thread_item;

    // Find out whether thread is already present in the tree or not.
    while (node) {

        struct pid *this = rb_entry(node, struct pid, ns[0].node);

        parent = *new;
        if (pid < this->ns[0].virt) {
            node = node->rb_left, new = &((*new)->rb_left);
        } else if (pid > this->ns[0].virt) {
            node = node->rb_right, new = &((*new)->rb_right);
        } else {

            // XXX: Shiv
            //
            // Handling thread leader case:
            // Here the address of struct pid for thread structure (our) and
            // pstree item will be different because process id of process
            // and tid of a leader thread is same.
            if (unlikely(is_thread_leader)) {

                // If it is not first time then just mark the leader thread as
                // non-deleted.
                if (!list_empty(&(item->threads))) {
                    thread_item = list_first_entry (&(item->threads), struct pstree_item_thread, thread_list);
                    thread_item->thread.is_deleted = false;
                } else {
                    thread_item = create_thread_item (item, pid, rst);
                }
                if (thread_item == NULL)
                    return NULL;
                return &(thread_item->thread);

            }
            this->is_deleted = false;
            return this;

        }

    }

    if (!pid_node) {

        // Thread is not found, so create it.
        thread_item = create_thread_item (item, pid, rst);
        if (thread_item == NULL)
            return NULL;

        // Get the pid node.
        pid_node = &(thread_item->thread);

    }

    // Insert into rb tree.
    rb_link_and_balance(pid_root_rb, &(pid_node->ns[0].node), parent, new);
    return pid_node;

}

void pstree_insert_pid_thread (struct pstree_item *item, struct pid *pid_node) {

    struct pid *n;
    n = lookup_create_thread (item, pid_node->ns[0].virt, pid_node, false, false);
    BUG_ON(n != pid_node);

}

void pstree_insert_pid(struct pid *pid_node)
{
	struct pid *n;

	n = lookup_create_pid(pid_node->ns[0].virt, pid_node);

	BUG_ON(n != pid_node);
}

struct pstree_item *lookup_create_item(pid_t pid)
{
	struct pid *node;

	node = lookup_create_pid(pid, NULL);
	if (!node)
		return NULL;
	BUG_ON(node->state == TASK_THREAD);

	return node->item;
}

struct pid *pstree_pid_by_virt(pid_t pid)
{
	struct rb_node *node = pid_root_rb->rb_node;

	while (node) {
		struct pid *this = rb_entry(node, struct pid, ns[0].node);

		if (pid < this->ns[0].virt)
			node = node->rb_left;
		else if (pid > this->ns[0].virt)
			node = node->rb_right;
		else
			return this;
	}
	return NULL;
}

// TODO: Next
// Write a reset function for this which will delete ids values from *_ns_desc
// lists in case they are not referred in this iteration.
static int read_pstree_ids(struct pstree_item *pi) {

	int ret;
	struct cr_img *img;

	img = open_image(CR_FD_IDS, O_RSTR, vpid(pi));
	if (!img)
		return -1;

    // TODO: Next
    // Update the pi->ids reading for iterative version where protobuf is taking
    // care of deserialising the structure in shared region.
	ret = pb_read_one_eof(img, &pi->ids, PB_IDS, true /*XXX: Later Check*/);
	close_image(img);

	if (ret <= 0)
		return ret;

	if (pi->ids->has_mnt_ns_id)
		if (rst_add_ns_id(pi->ids->mnt_ns_id, pi, &mnt_ns_desc))
			return -1;

	if (pi->ids->has_net_ns_id)
		if (rst_add_ns_id(pi->ids->net_ns_id, pi, &net_ns_desc))
			return -1;

	if (pi->ids->has_pid_ns_id)
		if (rst_add_ns_id(pi->ids->pid_ns_id, pi, &pid_ns_desc))
			return -1;

	return 0;

}

/**
 * Function to mark a pstree item as deleted (used for iterative
 * parallel-restore implementation).
 */
static inline void mark_pstree_item_deleted (struct pstree_item *item) {
    item->pid->is_deleted = true;
}

/**
 * XXX: Shiv
 *
 * @Idea:
 *
 * While processing pstree.img file in each migration iteration, we could
 * encounter 4 cases:
 * 1.) A new Root node (root process) is appeared for entire process tree.
 * 2.) Some intermediate node (process with children) disappeared.
 * 3.) Some leaf node (process with no children) disappeared.
 * 4.) Some new nodes (new processes with parent-child semantics) appeared.
 *
 * Return value:
 *      <0  -> on Error
 *      0   -> on EOF
 *      >0  -> on Successful Read
 */
static int read_one_pstree_item (struct cr_img *img, pid_t *pid_max, bool init) {

	struct pstree_item *pi;
	PstreeEntry *e;
	int ret, i;

	ret = pb_read_one_eof(img, &e, PB_PSTREE, false /*XXX: Later Check*/);
	if (ret <= 0) {
		return ret;
    }

	ret = -1;
	pi = lookup_create_item(e->pid);
	if (pi == NULL) {
		goto err;
    }
	//BUG_ON(pi->pid->state != TASK_UNDEF);

	/*
	 * All pids should be added in the tree to be able to find
	 * free pid-s for helpers. pstree_item for these pid-s will
	 * be initialized when we meet PstreeEntry with this pid or
	 * we will create helpers for them.
	 */
	if (lookup_create_item(e->pgid) == NULL) {
		goto err;
    }
	if (lookup_create_item(e->sid) == NULL) {
		goto err;
    }

	pi->pid->ns[0].virt = e->pid;
	if (e->pid > *pid_max)
		*pid_max = e->pid;
	pi->pgid = e->pgid;
	if (e->pgid > *pid_max)
		*pid_max = e->pgid;
	pi->sid = e->sid;
	if (e->sid > *pid_max)
		*pid_max = e->sid;
	pi->pid->state = TASK_ALIVE;

    if (e->ppid == 0) {

        if ((root_item) && (init)) {
            pr_err("Parent missed on non-root task "
                   "with pid %d, image corruption!\n",
                   e->pid);
            goto err;
        }
        root_item = pi;
        pi->parent = NULL;

    } else {

		struct pid *pid;
		struct pstree_item *parent;

		pid = pstree_pid_by_virt(e->ppid);
		if (!pid || pid->state == TASK_UNDEF || pid->state == TASK_THREAD) {
			pr_err("Can't find a parent for %d\n", vpid(pi));
			goto err;
		}


        // Take care of the case when a process is disappeared at sender side
        // in successive migration iteration and its children get reparent to
        // init process of that container (before dumping process tree info at
        // sender side).
        parent = pid->item;
        if (pi->parent == NULL) {
            pi->parent = parent;
            list_add (&pi->sibling, &parent->children);
        } else if (pi->parent != parent) {
            mark_pstree_item_deleted (pi->parent);
            pi->parent = parent;
            list_add (&pi->sibling, &parent->children);
        }

    }

	pi->nr_threads = e->n_threads;

    /**
	pi->threads = xmalloc(e->n_threads * sizeof(struct pid));
	if (!pi->threads)
		goto err;
    */

    for (i = 0; i < e->n_threads; i++) {

		struct pid *node;
        /**
		pi->threads[i].real = -1;
		pi->threads[i].ns[0].virt = e->threads[i];
		pi->threads[i].state = TASK_THREAD;
		pi->threads[i].item = NULL;
        */

		if (i == 0) {
            node = lookup_create_thread (pi, e->threads[i], NULL, true, true);
			continue; /* A thread leader is in a tree already */
        }

        node = lookup_create_thread (pi, e->threads[i], NULL, false, true);

        //node = lookup_create_pid (pi->threads[i].ns[0].virt, &pi->threads[i]);

		BUG_ON(node == NULL);

        /**
		if (node != &pi->threads[i]) {
			pr_err("Unexpected task %d in a tree %d\n", e->threads[i], i);
			goto err;
		}*/

    }

	task_entries->nr_threads += e->n_threads;
	task_entries->nr_tasks++;

	/* note: we don't fail if we have empty ids */
    // XXX:
    // Process ids file in first iteration only w.r.t. each process.
	if ((pi->curr_iter == 1) && (read_pstree_ids(pi) < 0)) {
		goto err;
    }

	ret = 1;
err:
	pstree_entry__free_unpacked(e, NULL);
	return ret;

}

static int read_pstree_image (pid_t *pid_max, bool init) {

	struct cr_img *img;
	int ret;

	pr_info("Reading image tree\n");

	img = open_image(CR_FD_PSTREE, O_RSTR);
	if (!img)
		return -1;

	do {
		ret = read_one_pstree_item(img, pid_max, init);
	} while (ret > 0);

	close_image(img);
	return ret;

}

#define RESERVED_PIDS 300
/**static int get_free_pid(void)
{
	static struct pid *prev, *next;

	if (prev == NULL)
		prev = rb_entry(rb_first(&pid_root_rb), struct pid, ns[0].node);

	while (1) {
		struct rb_node *node;
		pid_t pid;

		pid = prev->ns[0].virt + 1;
		pid = pid < RESERVED_PIDS ? RESERVED_PIDS + 1 : pid;

		node = rb_next(&prev->ns[0].node);
		if (node == NULL)
			return pid;
		next = rb_entry(node, struct pid, ns[0].node);
		if (next->ns[0].virt > pid)
			return pid;
		prev = next;
	}

	return -1;
}*/

/**
static int prepare_pstree_ids(pid_t pid)
{
	struct pstree_item *item, *child, *helper, *tmp;
	LIST_HEAD(helpers);

	pid_t current_pgid = getpgid(pid);

	 *
	 * Some task can be reparented to init. A helper task should be added
	 * for restoring sid of such tasks. The helper tasks will be exited
	 * immediately after forking children and all children will be
	 * reparented to init.
	list_for_each_entry(item, &root_item->children, sibling) {
		struct pstree_item *leader;

		 *
		 * If a child belongs to the root task's session or it's
		 * a session leader himself -- this is a simple case, we
		 * just proceed in a normal way.
		if (item->sid == root_item->sid || item->sid == vpid(item))
			continue;

		leader = pstree_item_by_virt(item->sid);
		BUG_ON(leader == NULL);
		if (leader->pid->state != TASK_UNDEF) {
			pid_t helper_pid;

			helper_pid = get_free_pid();
			if (helper_pid < 0)
				break;
			helper = lookup_create_item(helper_pid);
			if (helper == NULL)
				return -1;

			pr_info("Session leader %d\n", item->sid);

			helper->sid = item->sid;
			helper->pgid = leader->pgid;
			helper->ids = leader->ids;
			helper->parent = leader;
			list_add(&helper->sibling, &leader->children);

			pr_info("Attach %d to the task %d\n", vpid(helper), vpid(leader));
		} else {
			helper = leader;
			helper->sid = item->sid;
			helper->pgid = item->sid;
			helper->parent = root_item;
			helper->ids = root_item->ids;
			list_add_tail(&helper->sibling, &helpers);
		}
		if (init_pstree_helper(helper)) {
			pr_err("Can't init helper\n");
			return -1;
		}

		pr_info("Add a helper %d for restoring SID %d\n", vpid(helper), helper->sid);

		child = list_entry(item->sibling.prev, struct pstree_item, sibling);
		item = child;

		// Stack on helper task all children with target sid.
		list_for_each_entry_safe_continue(child, tmp, &root_item->children, sibling) {
			if (child->sid != helper->sid)
				continue;
			if (child->sid == vpid(child))
				continue;

			pr_info("Attach %d to the temporary task %d\n", vpid(child), vpid(helper));

			child->parent = helper;
			list_move(&child->sibling, &helper->children);
		}
	}

	// Try to connect helpers to session leaders
	for_each_pstree_item(item) {
		if (!item->parent) // skip the root task
			continue;

		if (item->pid->state == TASK_HELPER)
			continue;

		if (item->sid != vpid(item)) {
			struct pstree_item *parent;

			if (item->parent->sid == item->sid)
				continue;

			// the task could fork a child before and after setsid()
			parent = item->parent;
			while (parent && vpid(parent) != item->sid) {
				if (parent->born_sid != -1 && parent->born_sid != item->sid) {
					pr_err("Can't figure out which sid (%d or %d)"
					       "the process %d was born with\n",
					       parent->born_sid, item->sid, vpid(parent));
					return -1;
				}
				parent->born_sid = item->sid;
				pr_info("%d was born with sid %d\n", vpid(parent), item->sid);
				parent = parent->parent;
			}

			if (parent == NULL) {
				pr_err("Can't find a session leader for %d\n", item->sid);
				return -1;
			}

			continue;
		}
	}

	// All other helpers are session leaders for own sessions
	list_splice(&helpers, &root_item->children);

	// Add a process group leader if it is absent
	for_each_pstree_item(item) {
		struct pid *pgid;

		if (!item->pgid || vpid(item) == item->pgid)
			continue;

		pgid = pstree_pid_by_virt(item->pgid);
		if (pgid->state != TASK_UNDEF) {
			BUG_ON(pgid->state == TASK_THREAD);
			rsti(item)->pgrp_leader = pgid->item;
			continue;
		}

		 *
		 * If the PGID is eq to current one -- this
		 * means we're inheriting group from the current
		 * task so we need to escape creating a helper here.
		if (current_pgid == item->pgid)
			continue;

		helper = pgid->item;

		helper->sid = item->sid;
		helper->pgid = item->pgid;
		helper->pid->ns[0].virt = item->pgid;
		helper->parent = item;
		helper->ids = item->ids;
		if (init_pstree_helper(helper)) {
			pr_err("Can't init helper\n");
			return -1;
		}
		list_add(&helper->sibling, &item->children);
		rsti(item)->pgrp_leader = helper;

		pr_info("Add a helper %d for restoring PGID %d\n", vpid(helper), helper->pgid);
	}

	return 0;
}*/

/**
 * XXX: Shiv
 * In case of container migration, we are restricting ourself only for processes
 * having tree type structure inside container not like forest type structure.
 * And in this case, we only have to assign group leaders for each tasks.
 */
static int prepare_pstree_pgids (void) {

    struct pstree_item *item;

    // Add a process group leader, if it is absent.
    for_each_pstree_item(item) {

        struct pid *pgid;

        if (!item->pgid || vpid(item) == item->pgid)
            continue;

        pgid = pstree_pid_by_virt (item->pgid);
        if (pgid->state != TASK_UNDEF) {
            BUG_ON(pgid->state == TASK_THREAD);
            rsti(item)->pgrp_leader = pgid->item;
            continue;
        }

    }

    return 0;

}

static unsigned long get_clone_mask(TaskKobjIdsEntry *i, TaskKobjIdsEntry *p)
{
	unsigned long mask = 0;

	if (i->files_id == p->files_id)
		mask |= CLONE_FILES;
	if (i->pid_ns_id != p->pid_ns_id)
		mask |= CLONE_NEWPID;
	if (i->net_ns_id != p->net_ns_id)
		mask |= CLONE_NEWNET;
	if (i->ipc_ns_id != p->ipc_ns_id)
		mask |= CLONE_NEWIPC;
	if (i->uts_ns_id != p->uts_ns_id)
		mask |= CLONE_NEWUTS;
	if (i->time_ns_id != p->time_ns_id)
		mask |= CLONE_NEWTIME;
	if (i->mnt_ns_id != p->mnt_ns_id)
		mask |= CLONE_NEWNS;
	if (i->user_ns_id != p->user_ns_id)
		mask |= CLONE_NEWUSER;

	return mask;
}

static int prepare_pstree_kobj_ids(void)
{
	struct pstree_item *item;

	/* Find a process with minimal pid for shared fd tables */
	for_each_pstree_item(item) {
		struct pstree_item *parent = item->parent;
		TaskKobjIdsEntry *ids;
		unsigned long cflags;

		if (!item->ids) {
			if (item == root_item) {
				pr_err("No IDS for root task.\n");
				pr_err("Images currupted or too old criu was used for dump.\n");
				return -1;
			}

			continue;
		}

		if (parent)
			ids = parent->ids;
		else
			ids = root_ids;

		/*
		 * Add some sanity check on image data.
		 */
		if (unlikely(!ids)) {
			pr_err("No kIDs provided, image corruption\n");
			return -1;
		}

		cflags = get_clone_mask(item->ids, ids);

		if (cflags & CLONE_FILES) {
			int ret;

			/*
			 * There might be a case when kIDs for
			 * root task are the same as in root_ids,
			 * thus it's image corruption and we should
			 * exit out.
			 */
			if (unlikely(!item->parent)) {
				pr_err("Image corruption on kIDs data\n");
				return -1;
			}

			ret = shared_fdt_prepare(item);
			if (ret)
				return ret;
		}

		rsti(item)->clone_flags = cflags;
		if (parent)
			/*
			 * Mount namespaces are setns()-ed at
			 * restore_task_mnt_ns() explicitly,
			 * no need in creating it with its own
			 * temporary namespace.
			 *
			 * Root task is exceptional -- it will
			 * be born in a fresh new mount namespace
			 * which will be populated with all other
			 * namespaces' entries.
			 */
			rsti(item)->clone_flags &= ~CLONE_NEWNS;

		/**
		 * Only child reaper can clone with CLONE_NEWPID
		 */
		if (vpid(item) != INIT_PID)
			rsti(item)->clone_flags &= ~CLONE_NEWPID;

		cflags &= CLONE_ALLNS;

		if (item == root_item) {
			pr_info("Will restore in %lx namespaces\n", cflags);
			root_ns_mask = cflags;
		} else if (cflags & ~(root_ns_mask & CLONE_SUBNS)) {
			/*
			 * Namespaces from CLONE_SUBNS can be nested, but in
			 * this case nobody can't share external namespaces of
			 * these types.
			 *
			 * Workaround for all other namespaces --
			 * all tasks should be in one namespace. And
			 * this namespace is either inherited from the
			 * criu or is created for the init task (only)
			 */
			pr_err("Can't restore sub-task in NS\n");
			return -1;
		}
	}

	pr_debug("NS mask to use %lx\n", root_ns_mask);
	return 0;
}

/**
 * Function to mark all process and thread items as deleted.
 */
static void reset_pstree (void) {

    struct pstree_item *item;
    struct pstree_item_thread *thread_item;
    struct fdt *fdt;

    // Mark all process and thread items as deleted.
    for_each_pstree_item(item) {

        // First mark pstree item's pid as deleted.
        item->pid->is_deleted = true;
        item->task_updated = false;

        // Now if pstree item is having more than one thread then mark
        // those threads's pids as deleted as well.
        if (item->nr_threads >= 1) {
            list_for_each_entry(thread_item, &(item->threads), thread_list) {
                thread_item->thread.is_deleted = true;
            }
        }

    }

    // Reset root item fdt value to 1.
    fdt = rsti(root_item)->fdt;
    if (fdt) {
        fdt->nr = 1;
    }

}

/**
 * XXX: Shiv
 *
 * Function to clean pstree structure and other structure dependent on
 * pstree like threads, ids etc.
 *
 * @Idea:
 *
 * Here whatever data, e.g. process, thread etc. are not referred in current
 * iteration will be deleted:
 * 1.) A process is not referred.
 * 2.) A thread is not referred.
 *
 * XXX:
 * This function should be called at the end when non-referred created
 * processes or threads from previous iteration are killed.
 */
void clean_pstree (bool is_last_iter) {

    struct pstree_item *item, *parent;
    struct pstree_item_thread *thread_item, *ti;
    bool reusable = is_last_iter ? false : true;
    bool is_prestore = true;

    // Delete the non-referred process first.
    for_each_pstree_item(item) {

        // Delete the process along with its threads and others, if it is not
        // referred in this iteration.
        if (item->pid->is_deleted) {
            parent = item->parent;
            free_one_pstree_item (item, reusable, is_prestore);
            item = parent;
        } else {
            // Now clean each thread of that process.
            list_for_each_entry_safe (thread_item, ti, &(item->threads), thread_list) {
                if (thread_item->thread.is_deleted) {
                    list_del (&thread_item->thread_list);
                    fshfree_last (thread_item);
                }
            }
        }

    }

}

int prepare_pstree (bool init) {

	int ret;
	pid_t pid_max = 0, kpid_max = 0, pid;
	int fd;
	char buf[21];

    // XXX: Shiv
    // If it is not first parallel restore call then we have to reset pstree,
    // i.e, we have to change some info in pstree.
    if (!init) {
        reset_pstree ();
    }

	fd = open_proc(PROC_GEN, PID_MAX_PATH);
	if (fd >= 0) {
		ret = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (ret > 0) {
			buf[ret] = 0;
			kpid_max = strtoul(buf, NULL, 10);
			pr_debug("kernel pid_max=%d\n", kpid_max);
		}
	}

	ret = read_pstree_image(&pid_max, init);
	pr_debug("pstree pid_max=%d\n", pid_max);

	if (!ret && kpid_max && pid_max > kpid_max) {
		/* Try to set kernel pid_max */
		fd = open_proc_rw(PROC_GEN, PID_MAX_PATH);
		if (fd == -1)
			ret = -1;
		else {
			snprintf(buf, sizeof(buf), "%u", pid_max + 1);
			if (write(fd, buf, strlen(buf)) < 0) {
				pr_perror("Can't set kernel pid_max=%s", buf);
				ret = -1;
			} else
				pr_info("kernel pid_max pushed to %s\n", buf);
			close(fd);
		}
	}

	pid = getpid();

	if (!ret) {
		/*
		 * Shell job may inherit sid/pgid from the current
		 * shell, not from image. Set things up for this.
		 */
		ret = prepare_pstree_for_shell_job(pid);
    }
	if (!ret) {
		/*
		 * Walk the collected tree and prepare for restoring
		 * of shared objects at clone time
		 *
         * But before this reset shared fdt->nr counter to 1 in case of
         * successive migration iterations (look at *shared_fdt_prepare* function).
         */
		ret = prepare_pstree_kobj_ids();
    }
	if (!ret) {
		/*
		 * Session/Group leaders might be dead. Need to fix
		 * pstree with properly injected helper tasks.
		 */
        /**
         * XXX: Shiv
         *
         * For container migration, we don't need general session and group
         * management with the help of helper tasks as done in
         * **prepare_pstree_ids** function.
         *
         * Look at the comment written on that function.
         *
         */
        ret = prepare_pstree_pgids ();
    }

	return ret;

}

int prepare_dummy_pstree()
{
	pid_t dummy = 0;

	if (check_img_inventory(/* restore = */ false, true) == -1)
		return -1;

	if (prepare_task_entries() == -1)
		return -1;

	if (read_pstree_image(&dummy, true) == -1)
		return -1;

	return 0;
}

bool restore_before_setsid(struct pstree_item *child)
{
	int csid = child->born_sid == -1 ? child->sid : child->born_sid;

	if (child->parent->born_sid == csid)
		return true;

	return false;
}

struct pstree_item *pstree_item_by_virt(pid_t virt)
{
	struct pid *pid;

	pid = pstree_pid_by_virt(virt);
	if (pid == NULL)
		return NULL;
	BUG_ON(pid->state == TASK_THREAD);

	return pid->item;
}

struct pstree_item *pstree_item_by_real(pid_t real)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
        if (item->pid->is_deleted)
            continue;
		if (item->pid->real == real)
			return item;
	}
	return NULL;
}

int pid_to_virt(pid_t real)
{
	struct pstree_item *item;

	item = pstree_item_by_real(real);
	if (item)
		return vpid(item);
	return 0;
}
