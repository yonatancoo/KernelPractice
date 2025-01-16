# Stage 1:

A. How to print from the kernel: use the printk macro (or one of the various pr_{log_level} macros, depending on the need). 
B. How to compile a kernel module:
C.
    1. How to load/unload a kernel module: insmod for loading, rmmod for unloading & modprobe can do both while also being more user friendly (As an example, rmmode mentions that the command modprobe -r removes modules as well as their dependent modules, which is safer).
    2. How to see a list of loaded kernel modules: lsmod/kmod list can be used to show a list of all loaded kernel modules.