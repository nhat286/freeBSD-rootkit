#!/bin/sh
# this script is run right after reboot
# - if rootkit persists, try and dig them out
# - if rootkit doesn't persist, it should be clean
echo "STAGE 2 has been run!"


# === save the access/mod time of perl ===
echo "Storing access times perl /tmp"
rm -f /tmp/perlcheck
echo "perl#`stat -f "%Sa" -n '/usr/local/bin/perl'`" >> /tmp/perlcheck

