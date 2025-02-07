obj-m += LsModIntercepter.o
LsModIntercepter-objs := LsModIntercept.o ../common/ftrace_hooking/ftrace_hook.o

ccflags-y := -Wno-unknown-pragmas -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
