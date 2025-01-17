#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void) {
    pr_info("Hello world!");
    return 0; // Indicate module was initialized successfully.
}

void cleanup_module(void) {
    pr_info("Goodbye world!");
}

MODULE_LICENSE("GPL");