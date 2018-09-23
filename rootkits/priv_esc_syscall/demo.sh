#!/bin/sh

make 2>&1 > /dev/null

echo 'make sure the module is loaded'

echo 'syscall with incorrect password'
perl -e '$str = "1234";' -e 'syscall(210, $str);'

echo 'syscall with correct password (escalates us to root)'
perl -e '$str = "6447_priv_esc_passwd";' -e 'syscall(210, $str);'
