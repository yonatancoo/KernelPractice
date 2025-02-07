#include <linux/ftrace.h>

struct fthook {
    struct ftrace_ops ops;
    unsigned long original_function_ptr;
    unsigned long new_function_ptr;
};

int setup_hook(struct fthook *hook, char *func_to_override_name, unsigned long new_func_ptr);