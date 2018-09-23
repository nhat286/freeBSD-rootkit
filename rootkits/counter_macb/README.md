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
- However the very act of triggering a write to these logs by the kernel will also update the M and C times of these log files
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

### Byte Patching:

The source can be found in `/sys/ufs/ufs/ufs_vnops.c`
The disassembly can be done by doing: `objdump -M intel -d --start-address=0xc0e2e230 /boot/kernel/kernel | head -185`

The ufs_itimes function has been improved and expanded since the book came out:
- Now it is expanded into `ufs_itimes` and `ufs_locked_itimes`.
- `ufs_itimes` simply acquires and releases locks and calls the locked version in between
- In the file itself it might be easier to patch out the calls to the function rather than the internals ? will try experiment with that 


The command to be run (assuming sudo) is:
```
sed -i '' '/kld/d' /var/log/auth.log
```

Because of this we need to rollback `sed`'s Access time as well ! 
