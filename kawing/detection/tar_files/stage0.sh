#!/bin/sh
# This script will run right after rookit installation, pre-escalation

DETECTED=1  # exit $DETECTED to exit 1 
CLEAN=0

# rootkit heuristic score 
SCORE=0

# House-keeping, testing for existance of persistance script 
PERSIST="/usr/local/etc/rc.d/STARTUP.sh"
if [ ! -x $PERSIST ]
then
    echo "Creating persistence file ..."  >> /tmp/progress.log
    echo "#!/bin/sh" >> $PERSIST && chmod 755 $PERSIST
else
    echo "Persistence file already exists ..." >> /tmp/progress.log
fi

# ===== check Access time of /usr/bin/cc ====
# Since most groups will use cc to compile their LKM's 
# most likely a rootkit was installed
access=`stat -f "%Sa|%SB" -n /usr/bin/cc | cut -d\| -f1`
birth=`stat -f "%Sa|%SB"  -n /usr/bin/cc | cut -d\| -f2`

# check for access and birth time mismatch
[ "$access" != "$birth" ] && echo -e "cc has been executed recently\t[!]" && SCORE=$((SCORE += 1))

# ==== check Access time of /bin/rm ====
# Most groups will clean up their files after installation
# if they use the system rm instead of their own rm it will get updated
# most likely a rootkit was installed

access=`stat -f "%Sa|%SB" -n '/bin/rm' | cut -d\| -f1`
birth=`stat -f "%Sa|%SB"  -n '/bin/rm' | cut -d\| -f2`

# check for access and birth time mismatch
[ "$access" != "$birth" ] && echo -e "rm has been executed recently\t[!]" && SCORE=$((SCORE += 1))


# ==== run hashsum checks on binaries ====
# bring in our own md5 and cat, hash the binaries and compare to our hashsum file
# if there is any difference it should raise some flags

while read -r line
do
    file=`bin/echo $line | cut -d\  -f1`
    path=`bin/echo $line | cut -d\  -f2`
    hsum=`bin/echo $line | cut -d\  -f3`

    nsum=`bin/cat  $path | bin/md5`

if [ "$hsum" = "$nsum" ] 
then
    echo -e "[passed]\t $file"
else
    echo -e "$file:\tchecksum failed \t [!]" && SCORE=$((SCORE += 1))
fi

done < hashsums 

# ==== load a fake KLD and it should be at syscall offset 210 ====
#MSG="$(kldload bin/sc_example.ko 2>&1)"
#NUM=`bin/cat "$MSG" | grep -o "[0-9]+"`
#echo $NUM
#kldunload sc_example.ko

# ==== if stage one: run daemonized ktrace / truss to listen for syscalls and suspicious strings
# ==== if stage two: collect results and analyse ====

# ===== preserve access times of whoami , id, and ls ====
echo "Storing access times of whoami, id, and ls in /tmp"
rm -f /tmp/preserve
echo "ls#`stat -f "%Sa" -n '/bin/ls'`" >> /tmp/preserve
echo "id#`stat -f "%Sa" -n '/usr/bin/id'`" >> /tmp/preserve
echo "whoami#`stat -f "%Sa" -n '/usr/bin/whoami'`" >> /tmp/preserve

echo -e "===================\nRootkit Score: $SCORE/10\n==================="
