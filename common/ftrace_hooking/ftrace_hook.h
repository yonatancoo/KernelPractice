#include <linux/ftrace.h>

struct fthook {
    struct ftrace_ops ops;
    unsigned long original_function_address;
    unsigned long new_function_address;
};

int setup_kernel_func_hook(struct fthook *hook, char *func_to_override_name, unsigned long new_func_address);
int setup_syscall_hook(struct fthook *hook, int syscall_number, unsigned long new_func_address);
void remove_hook(struct fthook *hook);