# Stage 1:

Notes:
The M at the end of the 'make' command is used to tell the build system to fetch & return to the file from the current working directory (as we're telling it to run from the build folder under modules, and not the actual pwd).

MODULE_LICENSE("GPL") is required when using GPL libs (also causes an annoying compilation warning).

A. How to print from the kernel: use the printk macro (or one of the various pr_{log_level} macros, depending on the need) to print to the kernel log. 

B. How to compile a kernel module: Create a makefile & use kbuilds' obj-m += {file_name}.o - This tells kbuild to build a kernel module using the source file named {file_name}.c (after building {file_name}.o & linking it with its source file).
C.
1. How to load/unload a kernel module: insmod for loading, rmmod for unloading, & modprobe can do both while also being more user-friendly (as an example, rmmode mentions that the command modprobe -r removes modules as well as their dependent modules, which is safer).
2. How to see a list of loaded kernel modules: lsmod/kmod list can be used to show a list of all loaded kernel modules.

# Stage 2:
Read about strace & tried figuring out what the syscalls used by ls mean.
Tried reading from the start, but it seems that a substantial amount of calls aren't all that relevant.
Tried reading from the end, seems that getdents64 is the call responsible for getting the file names, which is then followed by write (which writes the result to the console).

If there's a way to intercept either of these calls, it should be possible to hide the file.
After looking around a bit for a way to intercept syscalls, I came across something called the "LD_PRELOAD trick".
LD_PRELOAD is an env variable that loads before any other library, thus allowing us to make the linker use our functions instead of the intended ones.

After trying to make that work for a while & failing, I read a bit about the sys_call_table, which is what the kernel uses to do sys calls (seems to no longer be the case in newer/long-term versions of Linux, but the one I'm using doesn't seem to be included in that list).

It took some time, but I managed to find the address of the call sys table using "cat /proc/kallsyms | grep sys_call_table". 

For now I do this manually. Once I manage to make the address override work, I will write a function that does so instead.

The issue now is that I can't manage to change the value of the cr0 register (which, when unchanged, forbids my module from overriding the addresses on the call sys table).

It seems that the command "write_cr0" no longer functions as it was modified to not work under certain circumstances. 
Found an article that suggested writing the inline assembly that write_cr0 used to 'execute' when called, which fixed the issue.

Override still doesn't seem to work.

The write function does not cause a kern alert in the kernel log as expected. 
While looking for a solution for some of the problems I've experienced so far, I've seen something regarding how sys call function signatures work differently than one would expect... Will look into it.

I tend to think that the issue now really is that the sys_call_table override method was patched in recent versions of Linux. I will downgrade and check again...

After downgrading, the system freezes the moment the address of write is overridden.
Hijacked worked for the first time! The reason it froze was due to the signature change I speculated about above; after changing it to receive register pointers, it works.

After trying to override the buffer argument of the write syscall & failing (the buffer won't always represent a string, which makes it harder to work with), I've decided to try and work with gedents64, which is the syscall used to retrieve information about the files in a given directory.

Struggled for a while with getting the results of getdents64. 
First I tried accessing the si register after casting the pointer to a linux_dirent struct, which obviously didn't work as getdents64 returns the linux_dirent64 struct.
Still, I couldn't access any of the fields in that struct without the machine freezing. 

It took some time, but I eventually remembered how user/kernel memory works and copied the actual dirent array from user space over to the kernel space. 
Working now on figuring out what to do with the data, some of it is nonsensical.

Pretty sure that was due to using the wrong pt_regs struct.

I think I've found the correct one, struggling to make it compile.
After fixing the pt_regs struct, the issue still wasn't solved; it seems I wasn't iterating properly through the array (either the type of the number I used to iterate with or the pointer of the array itself. Will need to figure out after I finish this step for good).

The hook is actually hiding the file now, but the 'last' file in the array shows up twice.
The total length I returned was too long; after fixing it, the duplication glitch was resolved. All that's left is to patch up the code & figure out the bug I experienced with the pointer types.

The bug was due to the pointer I was iterating over. The linux_dirents64 struct has a dynamic size, so normal pointer arithmatic doesn't work; once I turned it into a char pointer, iterating through the array worked as expected.
Now that the module is stable, I've deleted some of the code I kept due to 'suspicions'.

# Stage 3:
Started by running strace on netstat -a (such that all sockets will be displayed).
After glancing at the syscalls, there doesn't seem to be any specific call that netstat uses to retrieve information regarding open sockets.

Started looking at the files opened by the program, skipped over names that seemed irrelevant, until I found /proc/net/tcp.
After turning off the http server, reopening it, and comparing multiple times, it seems that /proc/net/tcp contains an up-to-date list of active tcp sockets (confirmed this via kernel archives).

Going back to /proc/net/tcp, a simple google search yields the following page: "https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt."
Which explains that the file is created/updated via the tcp4/6_seq_show functions. 

If we hijack these functions, we could use them to hide sockets.
After reading about how seq files work and then tcp4_seq_show's implementation, I believe it should be possible to extract the socket info from the socket_common struct (which seems to be available regardless of the state of the socket) and check whether it matches the socket we're trying to hide. If it is, simply don't call the original function and return success; otherwise, call the original function.

Tried finding tcp4_seq_show in kallsyms, and it was indeed there. 
I've managed to override the function's pointer, but I've yet to actually hook it (netstat crashes when running).
I'm guessing it has something to do with the function's signature, the main reason being that reverting the function (resetting it back to the original pointer) works.

I mixed up the concept of hooking a function via the syscall table & hooking functions in general. 
Reading now how hooking kernel function works.

Found an example of how to trace functions using ftrace (https://www.kernel.org/doc/html/v4.17/trace/ftrace-uses.html)
I then found an explanation of how to hook functions using ftrace by changing the value of the RIP registry to that of the function I'm interested in running (https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2).

Managed to hook the function and extract the local address of the TCP4 sockets.
All that's left to do is write the code that checks whether the current seq file being handled matches the IP/port we're trying to hide.

Read a bit & tested kallsyms_lookup_name (which does exactly what you'd expect). Added it to this stage and will add it to stage 2 as well.

# Stage-4
Started by running strace on "ps -e" (such that all user processes will be displayed) and read from the end to the beginning (by now I know that most of the first syscalls are related to memory allocation & setting up the call itself, rather than the calls that interest me).

I very quickly noticed that ps executes openat requests for each of the proc process "files" (while reading about proc/net/tcp I was curious as to why the proc directory had a lot of "files"/"directories" with seemingly random names—which turned out to be information regarding running processes sorted by their PIDs).

Preceding the first openat request for a proc file, a getdents64 call is executed on /proc/.

I'll start by trying to hide the process using the module I wrote in stage 2 (which will hide any files that start with that PID, which obviously isn't ideal—but it should be enough to show that my suspicions are correct).

POC worked. All that's left now is to use the module & ensure that the module in stage 2 only hides files in the /proc/ directory. 
I've found a way to get the file struct from the file descriptor on stack overflow (https://stackoverflow.com/questions/17885676/in-linux-how-can-i-get-the-filename-from-the-struct-file-structure-while-ste).

I suspect that because /proc/ is a virtual file system, the "file name" of the file descriptor received by getdents64 is "/" (or, in other words, the top hierarchy directory). So my proposed solution won't work.

I'll try to rethink my approach.

openat receives the file path, so I can safely try to 'hide' the file there by returning an error when the program tries to open it.
I was getting annoyed with recompiling the module whenever I wanted to change a parameter, so I checked whether it's possible to pass arguments to the compiled module—and it seems like it is (https://tldp.org/LDP/lkmpg/2.6/html/x323.html). 
If it works here, I'll update the previous stages as well.

# Stage-5
Since the main objective this time is to prevent packets from being received by a program, I couldn't use strace to quickly figure out the syscalls involved in the operation I'm trying to hijack.
Instead, I started out by watching a short guide that explains how to send and receive UDP packets in C (https://www.youtube.com/watch?v=5PPfy-nUWIM).

I figured that the guide would have to use some sort of syscalls to send & receive packets—which turned out to be correct.
sendto & recvfrom, specifically.

After reading about recvfrom, I saw that there are multiple implementations (read, recvfrom, recvmsg, and so on), which isn't ideal.
Knowing that these offer similar functionality, I tend to believe that they all use a very similar/the same command (at least when it comes to UDP) to receive/read new messages.

After looking around in the Linux kernel, I found a function named udp_recvmsg, which I could probably use to filter out UDP packets as needed.
But that is not the point of the exercise—which means I'll have to use a different approach, one that lets me trace all of the incoming packets and dictate whether or not they're allowed to 'pass'. In other words, a sort of simple firewall. 

After looking around for a way to filter out packets, I found netfilter/iptables.
From there, I read about netfilter hooks and found some resources for basic usage (https://blogs.oracle.com/linux/post/introduction-to-netfilter).

I used the article above to write a small module that drops ALL ICMP packets (just to see that it works like I expect it to).
Now I need to think of a way to make the filter generic, or at least make it easier to add protocols/new filters.

Got arp filtering to work.

# Stage-6
I used strace on lsmod to see which syscalls are called.
The output seemed pretty similar to ps, a /proc/ file read operation followed by a lot of console writes.

This time the proc file was /proc/modules, which seems to contain a list of all loaded modules.
Much like stage-3, assuming this file is updated via a seq_file function, it should be possible to hide a kernel module from that list by hooking onto the seq_file function that creates it.

I couldn't really find any information about how /proc/modules is created, so I opened the kernel source code and looked in /kernel/module.c (under the assumption it probably contains the code that does so).

By searching for functions that receive seq_file's as an input, I found m_show, which seemed to be the relevant function. 
Its name indicated as such, and it had all of the relevant seq_printf calls.

I used the code from stage-3 to hook m_show such that a kernel log was outputted when the function was called. 
I then called lsmod & checked the kernel log, which was full of the log messages I had set for m_show—which means that the function is probably the one responsible for initializing /proc/modules.

I then looked at m_show's implementation to see how I could prevent it from printing out a given kernel module—the first line of the function converts the "p" pointer to a module struct (via a call to a macro named list_entry).

I tried casting the pointer to that of a module struct and then printing the name value to the log. 
For reasons I'm trying to figure out, the name was offset by 8 bytes.
I'm leaning towards list_entry shifting the pointer 8 bytes forward for one reason or another, or maybe even the pointer itself (which is supposed to be 8 bytes on my 64-bit system being involved).

Still, shifting the name pointer 8 bytes back solved the issue. 
I then added a bit of code that returns success without calling the actual function when the module we're trying to hide comes up, which successfully hid the module from lsmod & kmod list without hurting its functionality/ability to be removed.

After reading about the list_entry macro, I realized that the reason the struct was shifted by 8 bytes. 
The p parameter is not the struct module itself; it's the list field, which comes after the state enum (which is 8 bytes in x64). 

That is to say, I was casting from the pointer of the list field, which is 8 bytes from the actual pointer of the struct.

After looking a bit more at the output of lsmod, I noticed that it prints (per module) the amount of modules that use it, and their names.
My current method does not handle such a case.

First of all, I decided to see what it'll take to hide the name of the module, as that is a much more obvious sign.
I tried hiding a module I knew was a dependency of an additional module and then searched for the module that's dependent in strace. Doing this led me to an openat syscall for a directory named "/sys/module/{module_name}/holders.

That directory seems to contain files named after the module's dependencies. 
That call is then followed by a getdents64 syscall, and then the module & its dependencies are written to the console.

I think that reusing my failed approach for stage 4 may work here (using the file descriptor to get the file path).

That approach didn't work because /proc/ is a virtual file system, such that the file descriptor used by getdents64 was referring to a file named "/" (as it IS running on /proc/, which is the highest hierarchy directory in the /proc/ virtual file system).

This approach WILL work here, as the file under /sys/ is nested. 
After importing the code from stage-2, tweaking it a bit & adding the path name validation, it seemed to work.

All that's left is to figure out how to decrement the "Used by" number.
Initially I thought that lsmod gets the number via /proc/modules (which in turn gets it from module_refcount), but that turned out not to be the case. 
Rereading strace led me to see that a file named "/sys/module/{module_name}/refcnt is opened & read for each of the modules.
As expected, the file's content is the number of modules referencing the current module.

Relying on the same approach I used for getdents64 on the read syscall (using the file descriptor to tell which file is being opened), it should be possible to "adjust" the contents of refcnt as needed.

# Appendix

1. Decided to make the module params editable via their /sys/ files in order to enable them to be changed during module runtime.
2. Moved "common" functions (functions used by multiple files) to a different file.
3. While testing stage-3, I saw that after "pinging" (curling) the hidden socket, an additional socket was created.
One that was not hidden by the module. That socket "belongs" to the "client", so while it's technically not the socket we're trying to hide, it does make it obvious that the socket exists.

After rereading tcp4_seq_show I saw that the ip and port of the socket are stored in different structs, depending on the current socket state.
Adding a switch statement that extracts the values from the correct struct fixed the issue.
4. While "playing" around with stage-6 I realized that a race condition was somewhat likely to happen when unhooking the read function hook.

After trying several different ways to solve (or get around) the race condition (two of which can be seen in the "read_fix_attempt" and "stage6/hide_by_refcnt_change" branches) I "went back to the drawing board", and tried seeing if there's a different, simpler way to change the value of refcnt.

While reading about the /sys/ file-system I decided to browse module.c again and came across show_refcnt, a hookable function that's used to populate the /sys/module/{module_name}/refcnt file.

Hooking it & changing the value it writes to the buffer worked, such that I no longer need to rely on hooking the read syscall.