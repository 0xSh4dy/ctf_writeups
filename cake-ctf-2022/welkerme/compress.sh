#!/bin/sh
gcc exploit.c -o exploit -static
cp exploit vm/debugfs
cp exploit vm/rootfs
cd vm/debugfs
mkdir -p sys dev tmp proc run
find . | cpio -H newc --owner root -o > ../debugfs.cpio
cd ..
cd ..
cd vm/rootfs
find . | cpio -H newc --owner root -o > ../rootfs.cpio
