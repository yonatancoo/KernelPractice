#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include "ftrace_hook.h"

void notrace callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs) {
    // To prevent an infinite loop.
    if (!within_module(parent_ip, THIS_MODULE)) {
        struct fthook *original_hook = container_of(op, struct fthook, ops);
        regs->ip = original_hook->new_function_address;
    }
}

int setup_hook_base(struct fthook *hook, unsigned long original_func_address, unsigned long new_func_address) {
    hook->ops.func = callback_func;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    hook->original_function_address = original_func_address;
    hook->new_function_address = new_func_address;

    ftrace_set_filter_ip(&hook->ops, hook->original_function_address, 0, 0);
    register_ftrace_function(&hook->ops);

    return 0;
}

int setup_kernel_func_hook(struct fthook *hook, char *func_to_override_name, unsigned long new_func_address) {
    unsigned long original_func_address = kallsyms_lookup_name(func_to_override_name);
    if (!original_func_address) {
        pr_warn("Failed to find %s!", func_to_override_name);            
        return -ENXIO;
    }

    return setup_hook_base(hook, original_func_address, new_func_address);
}

int setup_syscall_hook(struct fthook *hook, int syscall_number, unsigned long new_func_address) {
    unsigned long lookup_res = kallsyms_lookup_name("sys_call_table");
    if (!lookup_res) {
        pr_warn("Failed to get sys_call_table pointer!");
        return -ENXIO;
    }
    unsigned long *syscall_table = (unsigned long*)lookup_res;

    unsigned long original_syscall_pointer = syscall_table[syscall_number];
    return setup_hook_base(hook, original_syscall_pointer, new_func_address);
}