#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include "ftrace_hook.h"

void notrace callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs) {
    // To prevent an infinite loop.
    if (!within_module(parent_ip, THIS_MODULE)) {
        struct fthook *original_hook = container_of(op, struct fthook, ops);
        regs->ip = original_hook->new_function_ptr;
    }
}

int setup_hook(struct fthook *hook, char *func_to_override_name, unsigned long new_func_ptr) {
    hook->ops.func = callback_func;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    unsigned long original_func_ptr = kallsyms_lookup_name(func_to_override_name);
    if (!original_func_ptr) {
        pr_warn("Failed to find %s!", func_to_override_name);            
        return -1;
    }

    hook->original_function_ptr = original_func_ptr;
    hook->new_function_ptr = new_func_ptr;
    ftrace_set_filter_ip(&hook->ops, original_func_ptr, 0, 0);
    register_ftrace_function(&hook->ops);

    return 0;
}