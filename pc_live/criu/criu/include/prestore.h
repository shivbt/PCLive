#ifndef __CR_PRESTORE__H__
#define __CR_PRESTORE__H__

#include <stdint.h>
#include "pstree.h"

// Commands for parallel restore.
enum {
    PRST_CHANGE_IMG_FD_OFF = 1,
    PRST_EXIT,
    PRST_UPDATE
};

// Info types for parallel restore.
enum {
    PRST_INFO_LOCAL = 0,
    PRST_INFO_GLOBAL
};

struct prst_task {
    struct pstree_item *item;
    struct list_head l;
};

// XXX: Shiv
// Moved this struct here from cr-restore.c.
// All arguments should be above stack, because it grows down
struct cr_clone_arg {
    struct pstree_item *item;
    unsigned long clone_flags;

    CoreEntry *core;
};

extern int prst_update_task_with_children (struct cr_clone_arg *ca);
extern struct prst_message *prst_msg;
extern int prst_handle_commands (struct pstree_item *pi);
extern int prst_apply_updates (int curr_iter, bool is_last_iter);
extern void prst_send_command_async (struct pstree_item *item, int cmd);
extern void wait_for_all_acks (void);

#endif /* __CR_PRESTORE__H__ */
