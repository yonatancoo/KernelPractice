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
static unsigned long *syscall_table = (unsigned long *)0xffffffffb1400320; 
static original_write_t original_write_ptr;
 
#define unprotect_memory() \
({ \
    orig_cr0 =  read_cr0();\
    write_cr0(orig_cr0 & (~ 0x10000)); /* Set WP flag to 0 */ \
});
#define protect_memory() \
({ \
    write_cr0(orig_cr0); /* Set WP flag to 1 */ \
});
 
asmlinkage int new_write(unsigned int fd, const char __user *buf, size_t count) {
    // hijacked write
    printk(KERN_ALERT "Hijacked!");
    return original_write_ptr(fd, buf, count);
}
 
int load(void) {
    printk(KERN_ALERT "Hello world!");
    unprotect_memory();
    original_write_ptr = (original_write_t)syscall_table[__NR_write];
    syscall_table[__NR_write] = (unsigned long)new_write;
    protect_memory();
    return 0;
}
 
void unload(void) {
    unprotect_memory();
    syscall_table[__NR_write] = (unsigned long)original_write_ptr;  
    protect_memory();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");