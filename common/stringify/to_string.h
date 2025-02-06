#include <linux/types.h>

static const int IP_STRING_MAX_LEN = 15;

void ipaddr_to_string(__be32 ipaddr, char* ipaddr_string);