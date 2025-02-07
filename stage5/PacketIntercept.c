#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <stdbool.h>
#include "../common/stringify/to_string.h"

// Function prototype.
unsigned int handle_ip_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int handle_arp_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// Types & other consts.
static char *ip_to_hide = NULL;
module_param(ip_to_hide, charp, 0600);

// 0 means no port filter.
static unsigned int port_to_hide = -1;
module_param(port_to_hide, int, 0600);

static struct nf_hook_ops ip_trace_ops = { .hook = (nf_hookfn*)handle_ip_packet, .hooknum = NF_INET_LOCAL_IN, .pf = NFPROTO_IPV4, .priority = NF_IP_PRI_FIRST };
static struct nf_hook_ops arp_trace_ops = { .hook = (nf_hookfn*)handle_arp_packet, .hooknum = NF_ARP_IN, .pf = NFPROTO_ARP, .priority = INT_MIN };

bool filter_by_source_ip_port(__be32 source_address, int source_port) {
    char *ipaddr = kmalloc(IP_STRING_MAX_LEN, GFP_KERNEL);
    ipaddr_to_string(source_address, ipaddr);
    bool does_ip_match = !strcmp(ipaddr, ip_to_hide);
    kfree(ipaddr);

    if (port_to_hide == -1) {
        return does_ip_match;
    }

    return does_ip_match && (source_port == port_to_hide);
} 

unsigned int handle_ip_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    __be32 source_address = iph->saddr;
    unsigned int source_port = -2;

    // To add support for another ip protocol just add an additional case statement that extracts the port (if it exists).
    switch (iph->protocol) {
        case IPPROTO_UDP:
            source_port = (unsigned int)(ntohs(udp_hdr(skb)->source));
            break;
        case IPPROTO_TCP:
            source_port = (unsigned int)(ntohs(tcp_hdr(skb)->source));
        case IPPROTO_ICMP: 
            break;
    }

    if (filter_by_source_ip_port(source_address, source_port)) {
        pr_info("Dropping packet from ip address: %pI4 port: %d", &source_address, source_port);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

unsigned int handle_arp_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct arphdr *arphdr = arp_hdr(skb);

    if (htons(arphdr->ar_pro) == ETH_P_IP) {
        char *packet_data_pointer =(char*)arphdr + sizeof(struct arphdr);
        __be32 *source_protocol_address = (__be32*)(packet_data_pointer + arphdr->ar_hln);
        char *source_ip_addr = kmalloc(IP_STRING_MAX_LEN, GFP_KERNEL);
        ipaddr_to_string(*source_protocol_address, source_ip_addr);

        if (!strcmp(source_ip_addr, ip_to_hide)) {
            pr_info("Dropping arp packet sent from ip: %s", source_ip_addr);
            kfree(source_ip_addr);

            return NF_DROP;
        }

        kfree(source_ip_addr);
    }

    return NF_ACCEPT;
}

int load(void) {
    if (ip_to_hide == NULL) {
        pr_warn("ip to hide has not been set! Existing...");
        return -EINVAL;
    }

    pr_info("Initializing... ip to hide: %s port: %d", ip_to_hide, port_to_hide);
    nf_register_net_hook(&init_net, &ip_trace_ops);
    nf_register_net_hook(&init_net, &arp_trace_ops);
    pr_info("Initialized successfuly!");
    return 0;
}

void unload(void) {
    pr_info("Shutting down.");
    nf_unregister_net_hook(&init_net, &ip_trace_ops);
    nf_unregister_net_hook(&init_net, &arp_trace_ops);
    pr_info("Goodbye world...");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");