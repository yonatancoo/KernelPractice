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
struct linux_dirent64 {


    ino64_t        d_ino;    /* 64-bit inode number */


    off64_t        d_off;    /* Not an offset; see getdents() */


    unsigned short d_reclen; /* Size of this dirent */


    unsigned char  d_type;   /* File type */


    char           d_name[]; /* Filename (null-terminated) */
};
#define BUF_SIZE 1024
int
main(int argc, char *argv[])
{


    int                  fd;


    char                 d_type;


    char                 buf[BUF_SIZE];


    long                 nread;


    struct linux_dirent64  *d;


    fd = open(argc > 1 ? argv[1] : ".", O_RDONLY | O_DIRECTORY);


    if (fd == -1)


        err(EXIT_FAILURE, "open");


    for (;;) {


        nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE);


        if (nread == -1)


            err(EXIT_FAILURE, "getdents");


        if (nread == 0)


            break;


        printf("--------------- nread=%ld ---------------\n", nread);


        printf("inode#    file type  d_reclen  d_off   d_name\n");


        for (size_t bpos = 0; bpos < nread;) {


            d = (struct linux_dirent64 *) (buf + bpos);


            printf("%8lu  ", d->d_ino);


            d_type = *(buf + bpos + d->d_reclen - 1);


            printf("%-10s ", (d_type == DT_REG) ?  "regular" :


                             (d_type == DT_DIR) ?  "directory" :


                             (d_type == DT_FIFO) ? "FIFO" :


                             (d_type == DT_SOCK) ? "socket" :


                             (d_type == DT_LNK) ?  "symlink" :


                             (d_type == DT_BLK) ?  "block dev" :


                             (d_type == DT_CHR) ?  "char dev" : "???");


            printf("%4d %10jd  %s\n", d->d_reclen,


                   (intmax_t) d->d_off, d->d_name);


            bpos += d->d_reclen;


        }


    }


    exit(EXIT_SUCCESS);
}
