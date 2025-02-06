unsigned long hijack_syscall(int syscall_number, unsigned long call_overide_ptr);
void restore_syscall(int syscall_number, unsigned long original_call_ptr);