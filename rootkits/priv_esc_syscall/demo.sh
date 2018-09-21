#!/bin/sh

set -e

KLDNAME='priv_esc.ko'
PASSWD='6447_priv_esc_passwda'

make 2>&1 > /dev/null
kldload module/$KLDNAME || (kldunload $KLDNAME && kldload module/$KLDNAME)
./interface/interface $PASSWD
kldunload $KLDNAME
