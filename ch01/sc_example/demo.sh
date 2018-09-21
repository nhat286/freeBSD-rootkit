#!/bin/sh

set -e

KLDNAME='sc_example.ko'

make 2>&1 > /dev/null
kldload module/$KLDNAME || (kldunload $KLDNAME && kldload module/$KLDNAME)
./interface/interface "Hello, kernel!"
kldunload $KLDNAME
dmesg | tail -n 1
