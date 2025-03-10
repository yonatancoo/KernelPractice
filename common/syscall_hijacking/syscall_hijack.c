#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include "cr_memory_premissions.h"

unsigned long set_syscall(int syscall_number, unsigned long call_overide_address) {
    unsigned long lookup_res = kallsyms_lookup_name("sys_call_table");
    if (!lookup_res) {
        pr_warn("Failed to get sys_call_table pointer!");
        return 0;
    }
    unsigned long *syscall_table = (unsigned long*)lookup_res;

    unsigned long original_syscall_pointer = syscall_table[syscall_number];

    disable_write_protect();
    syscall_table[syscall_number] = call_overide_address;
    enable_write_protect();

    pr_info("Overided syscall succesfully!");
    return original_syscall_pointer;
}