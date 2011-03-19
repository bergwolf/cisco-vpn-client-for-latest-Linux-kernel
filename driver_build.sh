#!/bin/sh
##########################################################################
#           Copyright (c) 2001, Cisco Systems, All Rights Reserved
###########################################################################
#
#  File:    driver_build.sh
#  Date:    04/23/2001
#
###########################################################################
#
# A script to build the linux driver.
#
###########################################################################

usage() {
	echo "$0"
	echo "Cisco Systems VPN Client Version BUILDVER_STRING"
	echo "Copyright (C) 1998-2001 Cisco Systems, Inc. All Rights Reserved."
	echo ""
	echo "usage:"
	echo "    ./driver_build.sh 'kernel_src_dir'"
	echo ""
	echo "'kernel_src_dir' is the directory containing the linux kernel sour 
ce"
	echo ""
}

CC=cc
LD=ld

KSRCDIR=$1
if [ "x$KSRCDIR" = "x" ]; then
        usage
        exit 1
fi
if [ ! -d $KSRCDIR ]; then
        usage
        exit 1
fi

INCLUDES="-I. -I${KSRCDIR}/include"
if [ `uname -m` = "x86_64" ]; then
    CFLAGS="-O2 -DCNI_LINUX_INTERFACE -D__KERNEL__ -DMODULE -D_LOOSE_KERNEL_NAMES -DHAVE_CONFIG_H -mcmodel=kernel -mno-red-zone"
else
    CFLAGS="-O2 -DCNI_LINUX_INTERFACE -D__KERNEL__ -DMODULE -D_LOOSE_KERNEL_NAMES -DHAVE_CONFIG_H"
fi

case `uname -r` in
2.[56].*)
    make "KERNEL_SOURCES=${KSRCDIR}"
    ;;
*)
    $CC $CFLAGS $INCLUDES -c linuxcniapi.c
    $CC $CFLAGS $INCLUDES -c interceptor.c
    $CC $CFLAGS $INCLUDES -c IPSecDrvOS_linux.c
    $CC $CFLAGS $INCLUDES -c frag.c
    $CC $CFLAGS $INCLUDES -c linuxkernelapi.c
if [ `uname -m` = "x86_64" ]; then
  $LD -r -o cisco_ipsec linuxkernelapi.o frag.o linuxcniapi.o IPSecDrvOS_linux.o interceptor.o libdriver64.so
else  
  $LD -r -o cisco_ipsec linuxkernelapi.o frag.o linuxcniapi.o IPSecDrvOS_linux.o interceptor.o libdriver.so
fi
    ;;
esac

