#!/bin/sh

SHARED_FOLDER="$HOME/vmshare"
KERNEL_VERSION="5.4.0-rc3+"
COMPRESSED_IMAGE="./arch/x86/boot/bzImage"
CONFIG_FILE="./.config"
SYSTEM_MAP="./System.map"
rm -r $SHARED_FOLDER/*
make -j8 vmlinux
make -j8 bzImage

mkdir $SHARED_FOLDER/boot
cp $COMPRESSED_IMAGE $SHARED_FOLDER/boot/vmlinuz-$KERNEL_VERSION
cp $CONFIG_FILE $SHARED_FOLDER/boot/config-$KERNEL_VERSION
cp $SYSTEM_MAP $SHARED_FOLDER/boot/System.map-$KERNEL_VERSION