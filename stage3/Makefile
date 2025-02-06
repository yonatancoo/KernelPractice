obj-m += NetStatIntercepter.o
NetStatIntercepter-objs := NetStatIntercept.o ../common/stringify/to_string.o
 
ccflags-y := -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
