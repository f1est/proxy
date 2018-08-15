#!/bin/sh
PROJECTDIR=`pwd`

BCM_BUILDROOT=/opt/hndtools-arm-linux-2.6.36-uclibc-4.5.3
ALPHA_BUILDROOT=/opt/hndtools-arm-linux-2.6.36-uclibc-4.5.3
export TPATH_UC=$ALPHA_BUILDROOT
export TPATH_KC=$BCM_BUILDROOT
export TPATH_UCLIBC=$ALPHA_BUILDROOT 
export TPATH_LIBTGZ=$ALPHA_BUILDROOT/lib.tgz
export PATH=/opt/make-3.81:$BCM_BUILDROOT/bin:$PATH
export LD_LIBRARY_PATH=$ALPHA_BUILDROOT/lib

cd $PROJECTDIR/libs/libconfig/
make distclean

cd $PROJECTDIR/build
export STAGING_DIR=/opt/hndtools-arm-linux-2.6.36-uclibc-4.5.3/
export PATH="/opt/hndtools-arm-linux-2.6.36-uclibc-4.5.3/bin:$PATH"
cmake -DCMAKE_TOOLCHAIN_FILE=../crosscompile/dlink.cmake ../
make
