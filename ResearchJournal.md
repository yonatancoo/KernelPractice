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
After looking around a bit for way to intercept syscalls I came across something called the "LD_PRELOAD trick".
LD_PRELOAD is an env variable which loads before any other library, thus allowing us to make the linker use *our* functions instead of the intendend ones.

After trying to make that work for a while & failing, I read a bit about the sys_call_table, which is what the kernel uses to do sys calls (Seems to no longer be the case in newer / long term versions of linux, but the one I'm using doesn't seem to be included in that list).

It took some time but I managed to find the address of the call sys table using "cat /proc/kallsyms | grep sys_call_table" (For now I do this manually. Once I manage to make the address override work I will write a function which does this automatically)

The issue now is that I can't manage to change the value of the cr0 register (which when unchanged forbids my module from overriding the addresses on the call sys table).

It seems that the command "write_cr0" no longer functions as the cr0 register was pinned. 
Found an article which suggested just writing the inline assmebly which write_cr0 used to 'execute' when called, which fixed the issue.

Override still doesn't seem to work, write function does not cause a kern alert in the kern log as expected. 
While looking for solution for some of the problems I've expereinced so far I've seen something regarding the way function signatures are stored in the sys call table being changed... Will look into it.

I tend to think that the issue now really is that the sys_call_table override method was patched in recent versions of linux, will downgrade and check again...

After downgrading the system freezes the moment the address of write is overriden.
Hijacked worked for the first time! The reason it froze was due to the signature change I speculated about above, after changing it to receive registry pointers it works.

After trying to override the buffer passed on to write & failing (The buffer won't always represent a string, which makes it harder to work with) I've decided to try and work with gedents64, which is the sys call used to retreive information about the files in the directory.