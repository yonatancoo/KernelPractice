#define _GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    printf("Hello! \n");
    int fd = syscall(SYS_open, "/sys/module/hid/redfcnt");       
    char buf[32];

    int bytes_read = syscall(SYS_read ,fd, &buf, 31);

    printf("Buffer: %s \n", buf);
}