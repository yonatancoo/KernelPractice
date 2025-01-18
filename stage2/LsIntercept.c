#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
 
int new_write(unsigned int fd, const char __user *buf, size_t count);
int load(void);
void unload(void);

typedef asmlinkage int (*original_write_t)(unsigned int, const char __user *, size_t);
static unsigned long *syscall_table = (unsigned long *)0xffffffffba0001a0; 
static original_write_t original_write_ptr;
 
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

asmlinkage int new_write(unsigned int fd, const char __user *buf, size_t count) {
    printk(KERN_ALERT "Hijacked!");
    return original_write_ptr(fd, buf, count);
}
 
int load(void) {
    printk(KERN_ALERT "Initializing...");
    zero_cr0();
    original_write_ptr = (original_write_t)syscall_table[__NR_write];

    int fd = open("~/Desktop/file.txt", 0_RDWR | 0_CREAT, 0600)
    int write_attempt = ((original_write_t)0x0000000009347735)(fd, "hello", 5);

    printk(KERN_ALERT "%p OWP", original_write_ptr);
    // syscall_table[__NR_write] = (unsigned long)new_write;
    printk(KERN_ALERT "Overrided write ptr!");
    one_cr0();
    printk(KERN_ALERT "Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    zero_cr0();
    syscall_table[__NR_write] = (unsigned long)original_write_ptr;  
    one_cr0();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");