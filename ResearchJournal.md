# Stage 1:

Notes: 
the M at the end of the make command is used to tell make to fetch & return to the file from the current working directory (as we're telling it to run from the build folder under modules, and not the actual pwd)

MODULE_LICENSE("GPL") is required when using GPL libs.

A. How to print from the kernel: use the printk macro (or one of the various pr_{log_level} macros, depending on the need) to print to the kernel log. 
B. How to compile a kernel module: Create a makefile & use kbuilds' obj-m += {file_name}.o - this tells kbuild to build a kernel module using the source file named {file_name}.c (after building {file_name}.0 & linking it with it's source file).
C.
    1. How to load/unloadsa kernel module: insmod for loading, rmmod for unloading & modprobe can do both while also being more user friendly (As an example, rmmode mentions that the command modprobe -r removes modules as well as their dependent modules, which is safer).
    2. How to see a list of loaded kernel modules: lsmod/kmod list can be used to show a list of all loaded kernel modules.

# Stage 2:
Read about strace & tried figuring out what the syscals used by ls mean.
Tried reading from the start - but it seems that a substantial amount of lines aren't all that relevant.
Tried reading from the end - seems that getdents64 is the call responsible for getting the file names, which is then followed by write (which writes the result to the console).

If there's a way to intercept either of these calls it should be possible to hide the file.