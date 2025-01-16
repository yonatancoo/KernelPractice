#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void) {
    printk(KERN_INFO, "Hello world!");
    return 0; // Indicate module was initialized successfully.
}

void cleanup_module(void) {
    printk(KERN_INFO, "Goodbye world!");
}

MODULE_LICENSE("GPL");

