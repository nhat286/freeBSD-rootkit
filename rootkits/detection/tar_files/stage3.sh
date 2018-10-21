#!/bin/sh

# this script is run post-escalation, assuming the rootkit survices reboot
# again see if theres any changes made since the previous stage 
echo "STAGE3 has been run!"

SCORE=0

# === check that perl hasn't been executed since check ===
    perl_time=`grep "perl" /tmp/perlcheck | cut -d# -f2`
    curr_perl=`stat -f "%Sa" -n '/usr/local/bin/perl'`

    if [ "$perl_time" != "$curr_perl" ]
    then
        echo -e "perl access time has changed!\t[!]"
        SCORE=$((SCORE += 1))
    fi

echo -e "===================\nRootkit Score: $SCORE/10\n==================="
