# Stuff I've tried so far

## Useful command to check for file timestamp difference:
```
stat -f '%n%N: %n%tModified:%t%Sm%n%tAccess:%t%t%Sa%n%tChanged:%t%Sc%n%tBirth:%t%t%SB%n' /tmp
```

## EASY WAY:
_not bulletproof in terms of detection though_  


Using `touch` to reset the Access and Modified time  
To reset the **Change** time however it requires updating the system time:
- We can do this on FreeBSD by doing `date <TIME>` ie. `date 1432` will update the current time of the date to 2:32pm without changing the date
- However the very act of triggering a write to these logs by the kernel will also update these log files
    - It is easy to check for mismatch in updates though, as the change/modified time should match excatly the timestamp of the most recent message !!!  

Example: 
- https://i.imgur.com/alVRrT6.png
- https://www.shellhacks.com/fake-file-access-modify-change-timestamps-linux/ 



## HARD WAY:
_bulletproof for detection, but may fail/crash during execution depending on system_  

- Involves kernel code byte patching to mess around with `ufstimes` function

To predict the sequence of bytes in kernel (to avoid fail in kvm writes ultimately leading to crash):  
- We could try hashing the kernel and saving it to corresponding to a particular byte sequence

- There doesn't seem to be much overhead anyways:  
```
        $ time echo -n "hello" | md5
            0.02 real         0.00 user         0.00 sys
        5d41402abc4b2a76b9719d911017c592
        $ time md5 /boot/kernel/kernel
        MD5 (/boot/kernel/kernel) = 2e1e5ecbe821d840b2f9f38548997d11
            0.10 real         0.08 user         0.01 sys
``` 

