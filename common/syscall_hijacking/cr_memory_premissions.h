#include <linux/kernel.h>
#include <asm/special_insns.h>

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

MODULE_LICENSE("GPL");