#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include "cr_memory_premissions.h"

unsigned long hijack_syscall(int syscall_number, unsigned long call_overide_ptr) {
    unsigned long *syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    if (syscall_table == NULL) {
        pr_warn("Failed to get sys_call_table pointer!");
        return 0;
    }

    unsigned long original_syscall_pointer = syscall_table[syscall_number];

    disable_write_protect();
    syscall_table[syscall_number] = call_overide_ptr;
    enable_write_protect();

    pr_info("Overided syscall succesfully!");
    return original_syscall_pointer;
}

void restore_syscall(int syscall_number, unsigned long original_call_ptr) {
    unsigned long *syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    if (syscall_table == NULL) {
        pr_warn("Failed to get sys_call_table pointer!");
    }

    disable_write_protect();
    syscall_table[syscall_number] = original_call_ptr;  
    enable_write_protect();

    pr_info("syscall has been restored!");
}