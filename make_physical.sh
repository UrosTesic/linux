#!/bin/sh

make -j8 tar-pkg
tar -xvf ./linux-5.4.0-rc3+-x86.tar -C /media/tesic/a276793f-5f47-4bd6-a56b-a9032308e51c/
find /media/tesic/a276793f-5f47-4bd6-a56b-a9032308e51c/lib/modules/5.4.0-rc3+/ -iname "*.ko" -exec strip --strip-unneeded {} +
reboot