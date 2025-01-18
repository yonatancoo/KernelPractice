#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
 
typedef asmlinkage int (*original_write_t)(unsigned int, const char __user *, size_t);

static int orig_cr0;
static unsigned long *syscall_table = (unsigned long *)0xffffffff9be00320; 
static original_write_t original_write_ptr;
 
static inline void wp_cr0(unsigned long val) {
    __asm__ __volatile__ ("mov %0, %%cr0": "+r" (val));
}

static inline void zero_cr0(void) {
     wp_cr0(read_cr0() & (~0x10000));
}

static inline void one_cr0(void) {
   wp_cr0(read_cr0() | 0x10000);
}

asmlinkage int new_write(unsigned int fd, const char __user *buf, size_t count) {
    // hijacked write
    printk(KERN_ALERT "Hijacked!");
    return original_write_ptr(fd, buf, count);
}
 
int load(void) {
    printk(KERN_ALERT "Hello world!");
    printk(KERN_ALERT "Unprotecting mem!");
    zero_cr0();
    original_write_ptr = (original_write_t)syscall_table[__NR_write];
    printk(KERN_ALERT "Acquired write ptr!");
    syscall_table[__NR_write] = (unsigned long)new_write;
    printk(KERN_ALERT "Overrided write ptr!");
    printk(KERN_ALERT "Protecting mem...");
    one_cr0();
    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Unprotecting mem!");
    zero_cr0();
    syscall_table[__NR_write] = (unsigned long)original_write_ptr;  
    printk(KERN_ALERT "Protecting mem...");
    one_cr0();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");