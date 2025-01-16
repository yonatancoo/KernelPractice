#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void) {
    printk("Hello world!");
    return 0; // Indicate module was initialized successfully.
}

void cleanup_module(void) {
    printk("Goodbye world!");
}

