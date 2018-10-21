#!/bin/sh
# This script will run post-escalation, pre reboot
# the shell will be active and run some commands

# possible ideas
# 1. check for running shell in process
# 2. check for binary timestamps being updated since previous scan

DETECTED=1  # exit $DETECTED to exit 1 
CLEAN=0

# rootkit heuristic score 
SCORE=0

echo ">>>>>STAGE 1 has been run"

echo "checking preserved binaries access time since previous stage"
if [ -f /tmp/preserve ]
then
    # ==== check the access times compared to preserve ====
    ls_time=`grep "ls" /tmp/preserve | cut -d# -f2`
    curr_ls=`stat -f "%Sa" -n '/bin/ls'`

    if [ "$ls_time" != "$curr_ls" ]
    then
        echo -e "ls access time has changed!\t[!]"
        SCORE=$((SCORE += 1))
    fi


    id_time=`grep "id" /tmp/preserve | cut -d# -f2`
    curr_id=`stat -f "%Sa" -n '/usr/bin/id'`

    if [ "$id_time" != "$curr_id" ]
    then
        echo -e "id access time has changed]\t[!]"
        SCORE=$((SCORE += 1))
    fi


    whoami_time=`grep "whoami" /tmp/preserve | cut -d# -f2`
    curr_whoami=`stat -f "%Sa" -n '/usr/bin/whoami'`

    if [ "$whoami_time" != "$curr_whoami" ]
    then
        echo -e "whoami access time has changed]\t[!]"
        SCORE=$((SCORE += 1))
    fi

else
    # if the file was deleted that means something is not right
    echo "The file is missing !" && SCORE=$((SCORE += 1))    
fi

echo -e "===================\nRootkit Score: $SCORE/10\n==================="


