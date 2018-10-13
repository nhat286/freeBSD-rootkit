#!/bin/sh

# the script is run after remote OOB activity is run by the rootkit
# check for:
#   network connections
#   port knocking
#   extra files
#   keylogger files 

SCORE=0

echo "STAGE4 has been run !"

echo "==== checking for hidden files in /root folder (keyloggers etc) ===="
ls_count=`ls -a /root | wc -l`
check_count=$(echo -e "`file /root/*`\n`file /root/.*`"|egrep -v 'No such file or directory'|wc -l)

[ $ls_count -ne $check_count ] && echo -e "Hidden files in /root detected\t[!]" && SCORE=$((SCORE += 1))

echo -e "===================\nRootkit Score: $SCORE/10\n==================="

