#include <stdio.h>

#include "rst-fmalloc.h"
#include "prestore.h"
#include "restorer.h"
#include "log.h"
#include "common/bug.h"
#include "cr_options.h"
#include "cr-service.h"

static LIST_HEAD (prst_killed_tasks);

/**
 * Function to free a list containing created/ killed tasks info (prst_task type).
 */
static inline void __prst_free_tasks_list (struct list_head *prst_list) {

    struct prst_task *task, *tmp;

    if (list_empty (prst_list))
        return;

    list_for_each_entry_safe (task, tmp, prst_list, l) {
        list_del (&task->l);
        xfree (task);
    }

}

/**
 * Function to kill the task hierarchy starting from this task.
 */
static inline void __prst_exit_task (struct pstree_item *item) {

    struct pstree_item *pi;

    if (list_empty(&item->children))
        return;

    // Get the children in this subtree.
    item = pstree_item_next (item);

    // Kill all children of this task.
    for_each_pstree_item_current (item, pi) {
        if (pi->pid->real > 0) {
            kill (pi->pid->real, SIGKILL);
        }
    }

}

/**
 * Function to handle one command from pCRIU.
 */
static inline int __prst_handle_one_command (struct pstree_item *pi) {

    struct prst_message *prst_msg = &(pi->prst_msg);
    struct cr_clone_arg ca;
    bool is_exit = false;
    int ret = 0;
    int img_dir;

    // Handle the command.
    switch (prst_msg->cmd) {

        case PRST_CHANGE_IMG_FD_OFF:

            // First close previous image directory and then open current one.
            sfds_protected = false;
            close_image_dir ();
            img_dir = (opts.rp + pi->glob_iter - 1);
            ret = setup_images_dir (img_dir, true, false);
            sfds_protected = true;
            break;

        case PRST_EXIT:

            // Here entire process subtree is killed at once.
            __prst_exit_task (pi);
            is_exit = true;
            break;

        case PRST_UPDATE:

            // Fill the arg passed to restore_task_with_children function.
            // Open core for last iteration only.
            ca.item = pi;
            ca.clone_flags = rsti(pi)->clone_flags;
            sfds_protected = false;
            ret = prst_update_task_with_children (&ca);
            sfds_protected = true;
            break;

        default:
            BUG();

    }

    // And finally reset the notif flag for this task and set ack.
    prst_msg->ret_code = ret;
    futex_set (&pi->notif, 0);
    if (is_exit) {
        futex_set_and_wake (&prst_msg->ack, 1);
        exit (0);
    }

    return ret;

}

/**
 * Function to wait for next command from pCRIU and handle the command.
 */
int prst_handle_commands (struct pstree_item *pi) {

    struct prst_message *prst_msg = &(pi->prst_msg);
    int ret = 0;
    int done = 0;

    // By default all new task will set the acks to 1.
    futex_set_and_wake (&prst_msg->ack, 1);

    while (!done) {

        // First wait for the pCRIU process to signal this process.
        futex_wait_until (&pi->notif, 1);

        // Now handle the command.
        ret = __prst_handle_one_command (pi);
        if (ret || (prst_msg->cmd == PRST_UPDATE && pi->is_last_iter))
            done = 1;

        // Now send the ack.
        futex_set_and_wake (&prst_msg->ack, 1);

    }

    return ret;

}

static inline int __signal_task_for_mem_update (int virt_pid) {

    // Inform the process to start updating its memory content.
    int value;
    struct pstree_item *item = get_pstree_item_virt_iter (virt_pid);
    BUG_ON (item == NULL);
    futex_set_and_wake (&item->mem_notif, 1);

    // Wait for transfer completion of this process's pages, once done then
    // signal the process.
    if (wait_for_go_signal_data (&value)) {
	    return -1;
    }
    if (value == -1) {
	    futex_set (&item->xfer_complete, 1);
    } else {
	    BUG_ON (true);
    }

    return 0;

}

static inline void __prst_send_command_sync (struct pstree_item *item, int cmd) {

    // Prepare the message.
    struct prst_message *prst_msg = &(item->prst_msg);
    prst_msg->cmd = cmd;
    futex_set (&prst_msg->ack, 0);

    // Now signal the task to act on this message and wait for ack.
    futex_set_and_wake (&item->notif, 1);
    futex_wait_until (&prst_msg->ack, 1);

}

void prst_send_command_async (struct pstree_item *item, int cmd) {

    // Prepare the message.
    struct prst_message *prst_msg = &(item->prst_msg);
    prst_msg->cmd = cmd;
    futex_set (&prst_msg->ack, 0);

    // Now signal the task to act on this message.
    futex_set_and_wake (&item->notif, 1);

}

void wait_for_all_acks (void) {

    struct pstree_item *item;

    // Iterate throgh all tasks and wait for each acknowledgement.
    for_each_pstree_item(item) {

        struct prst_message *prst_msg = &(item->prst_msg);

        // Skip newly added tasks in this iteration.
        if (!item->task_created || item->pid->is_deleted)
            continue;

        futex_wait_until (&prst_msg->ack, 1);

    }

}

/**
 * Function to send message to change the image directory for all the tasks.
 */
static int prst_change_img_dir (int curr_iter, bool is_last_iter) {

    struct pstree_item *item;

    for_each_pstree_item(item) {

        // Update the last iteration flag for every task.
        item->is_last_iter = is_last_iter;

        // Skip newly added tasks in this iteration.
        if (!item->task_created || item->pid->is_deleted)
            continue;

        // Update the current iteration flag for already created tasks only.
        item->curr_iter++;
		item->glob_iter = curr_iter;

        // And finally send the command to update image directory.
        __prst_send_command_sync (item, PRST_CHANGE_IMG_FD_OFF);

        if (item->prst_msg.ret_code) {
            pr_perror ("Error: Task %d (vpid: %d) -> Setting image dir fd\n"
                    , item->pid->real, vpid(item));
            return -1;
        }

    }

    // Success return.
    return 0;

}

/**
 * Function to check whether root task of a subtree containing the given task
 * is already present in the lists (created/ deleted).
 */
static inline bool prst_root_is_already_added (struct pstree_item *item
        , struct list_head *prst_list) {

    struct prst_task *added_task;
    if (list_empty (prst_list))
        return false;

    // XXX: Shiv
    //
    // Traverse from down to top and check whether root of this task's subtree
    // is already present or not.
    //
    // Here I am assuming that root task of entire big task tree will not
    // touch this function call.
    while (item->parent) {
        list_for_each_entry (added_task, prst_list, l)
            if (item == added_task->item)
                return true;
        item = item->parent;
    }

    // Not found.
    return false;

}

/**
 * Function to add a task to the lists which will be used to orchestrate
 * the new task tree.
 */
static inline int prst_add_task (struct pstree_item *item
        , struct list_head *prst_list) {

    struct prst_task *new_task = NULL;

    // Add the task to the given list, if root task of its subtree is
    // not there in the that list.
    if (prst_root_is_already_added (item, prst_list))
        goto skip_add;

    new_task = xmalloc (sizeof(*new_task));
    if (!new_task) {
        pr_perror ("Not able to add pstree item (%d) in created list\n", item->pid->ns[0].virt);
        return 1;
    }

    new_task->item = item;
    list_add_tail (&new_task->l, prst_list);

skip_add:
    return 0;

}

/**
 * Function to identify died/ killed tasks in current iteration. And then
 * prepare a list for deleted/ killed tasks.
 */
static int identify_killed_tasks (void) {

    struct pstree_item *pi;
    for_each_pstree_item (pi) {
        if (pi->pid->is_deleted) {
            if (prst_add_task (pi, &prst_killed_tasks))
                return 1;
        }
    }

    // Simple success return.
    return 0;

}

static inline void __orchestrate_killed_task_tree (struct list_head *prst_list, int cmd) {

    struct prst_task *task;

    if (list_empty (prst_list))
        return;

    list_for_each_entry (task, prst_list, l) {
        __prst_send_command_sync (task->item, cmd);
    }

}

int signal_tasks_for_mem_update (void) {

    int i;

    // Wait for memory content dumping started signal from xfer-server for each
    // container process in the current iteration and then inform that process
    // to start processing memory content.
    for (i = 0; i < task_entries->nr_tasks; i++) {
        int virt_pid;
        if (wait_for_go_signal(&virt_pid)) {
            pr_perror ("Error while waiting for go signal from xfer-server.\n");
            return -1;
        }
        if (__signal_task_for_mem_update (virt_pid)) {
		return -1;
	}
    }

    return 0;

}

/**
 * Function to orchestrate task tree for iterative parallel restore.
 */
static int orchestrate_task_tree_changes (bool is_last_iter) {

    // First orchestrate process kill.
    __orchestrate_killed_task_tree (&prst_killed_tasks, PRST_EXIT);

    // Now orchestrate changes happened in current iteration.
    prst_send_command_async (root_item, PRST_UPDATE);

    // Now free the killed list.
    __prst_free_tasks_list (&prst_killed_tasks);

    // Signal tasks for memory updates if memory dumping is started.
    if (signal_tasks_for_mem_update())
        return -1;

    return 0;

}

/**
 * Function to apply all the updates happened in the current iteration, e.g.,
 * task tree change, memory related info change, file related info change etc.
 */
int prst_apply_updates (int curr_iter, bool is_last_iter) {

    int ret = -1;

    if (prst_change_img_dir (curr_iter, is_last_iter))
        goto err;

    wait_for_all_acks ();

    if (identify_killed_tasks ())
        goto err;

    if (orchestrate_task_tree_changes (is_last_iter))
        goto err;

    wait_for_all_acks ();

    // Now clean pstree metadata to get rid of disappeared processes in
    // successive iteration.
    clean_pstree (is_last_iter);

    // Everything is successfully done.
    ret = 0;

err:
    return ret;

}
