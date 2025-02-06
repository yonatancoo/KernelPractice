obj-m += LsIntercepter.o
LsIntercepter-objs := LsIntercept.o ../common/syscall_hijacking/syscall_hijack.o

ccflags-y := -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
