* Checks whether the syscall function pointers within the sysent array have been modified.
* The address detection kernel module will fail to load if the addresses have been tampered with.
* Because there is no KASLR and because the sysent table, syscall functions, and syscall function pointers are initialized during boot, the syscall function addresses will always be the same.
* The default addresses of different syscall functions are in the file `sy_call_addresses.txt`.
* The `tests` directory contains some poor implementations of syscall function pointer redirection. Please read the C files in `tests` to check for how to test each of them.
