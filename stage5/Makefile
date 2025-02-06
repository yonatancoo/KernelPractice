obj-m += PacketIntercepter.o
PacketIntercepter-objs := PacketIntercept.o ../common/stringify/to_string.o

ccflags-y := -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
