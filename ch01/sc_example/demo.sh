#!/bin/sh

set -ex

make
kldunload sc_example.ko || kldload module/sc_example.ko
./interface/interface "Hello, kernel!"
kldunload sc_example.ko
dmesg | tail -n 1
