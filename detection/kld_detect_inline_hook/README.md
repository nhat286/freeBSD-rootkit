* Checks whether the syscall functions have inline hooks (jumps or calls) to other locations.
* The inline hook detection will fail to load if the first few instruction bytes do not match the common function prologue of syscalls.
