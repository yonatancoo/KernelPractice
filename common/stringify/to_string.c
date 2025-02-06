#include <linux/types.h>
#include <linux/kernel.h>

void ipaddr_to_string(__be32 ipaddr, char* ipaddr_string) {
    int first = (unsigned char)(ipaddr & 0xFF);
    int second = (unsigned char)((ipaddr >> 8) & 0xFF);
    int third = (unsigned char)((ipaddr >> 16) & 0xFF);
    int fourth = (unsigned char)((ipaddr >> 24) & 0xFF);

    // Maximum length of an ip string in ipv4
    sprintf(ipaddr_string, "%d.%d.%d.%d", first, second, third, fourth);
}