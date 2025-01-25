#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>
#include <stdbool.h>

// Function prototype.
unsigned int handle_ip_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// Types & other consts.
static char *ip_to_hide;
module_param(ip_to_hide, charp, 0);

// 0 means no port filter.
static unsigned int port_to_hide = 0;
module_param(port_to_hide, int, 0);

static struct nf_hook_ops nf_tracer_ops = { .hook = (nf_hookfn*)handle_ip_packet, .hooknum = NF_INET_LOCAL_IN, .pf = NFPROTO_IPV4, .priority = NF_IP_PRI_FIRST };

char * ipaddr_to_string(__be32 ipaddr)
{
    int first = (unsigned char)(ipaddr & 0xFF);
    int second = (unsigned char)((ipaddr >> 8) & 0xFF);
    int third = (unsigned char)((ipaddr >> 16) & 0xFF);
    int fourth = (unsigned char)((ipaddr >> 24) & 0xFF);

    // Maximum length of an ip string in ipv4
    char *buffer = kmalloc(15 * 8, GFP_KERNEL);
    sprintf(buffer, "%d.%d.%d.%d", first, second, third, fourth);

    return buffer;
}

bool filter_by_source_ip_port(__be32 source_address, int source_port) {
    char* ipaddr = ipaddr_to_string(source_address);
    printk(KERN_ALERT "ip addr: %s port: %d", ipaddr, source_port);
    bool does_ip_match = !strcmp(ipaddr, ip_to_hide);

    if (!port_to_hide) {
        return does_ip_match;
    }

    return does_ip_match && (source_port == port_to_hide);
} 

unsigned int handle_ip_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    __be32 source_address = iph->saddr;
    unsigned int source_port = 0;

        // To add support for another ip protocol just add an additional case statement that extracts the port.
    switch (iph->protocol) {
        case IPPROTO_UDP:
            source_port = (unsigned int)(ntohs(udp_hdr(skb)->source));
            break;
        case IPPROTO_TCP:
            source_port = (unsigned int)(ntohs(tcp_hdr(skb)->source));
        case IPPROTO_ICMP: 
            printk(KERN_ALERT "icmp packet recevied, no port will be extracted!");
            break;
    }

    if (filter_by_source_ip_port(source_address, source_port)) {
        return NF_DROP;
    }

    return NF_ACCEPT;
}

int load(void) {
    printk(KERN_ALERT "Initializing...");
    nf_register_net_hook(&init_net, &nf_tracer_ops);
    printk(KERN_ALERT "Initialized successfuly!");
    return 0;
}

void unload(void) {
    printk(KERN_ALERT "Shutting down.");
    nf_unregister_net_hook(&init_net, &nf_tracer_ops);
    printk(KERN_ALERT "Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");