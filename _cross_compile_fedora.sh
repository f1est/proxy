#!/bin/bash

export PROJECTDIR=/home/Jokiv/projects/le-EmbediProxy/
export TOOLSDIR=/opt/hndtools-arm-linux-2.6.36-uclibc-4.5.3/
#export TARGETMACH=arm-none-linux-gnueabi
export BUILDMACH=i686-pc-linux-gnu
export CROSS=arm-brcm-linux-uclibcgnueabi
export TARGETMACH=${CROSS}

export STAGING_DIR=${TOOLSDIR}
export PATH=${TOOLSDIR}bin:$PATH
export CC=${CROSS}-gcc
export LD=${CROSS}-ld
export AS=${CROSS}-as
export AR=${CROSS}-ar
export STRIP=${CROSS}-strip

#export SSL_PATH=${PROJECTDIR}libs/openssl-1.0.2l/
export LIBCONFIG_PATH=${PROJECTDIR}libs/libconfig/
export LIBEVENT_PATH=${PROJECTDIR}libs/libevent/
export SYSTEM_LIBS=/opt/hndtools-arm-linux-2.6.36-uclibc-4.5.3/arm-brcm-linux-uclibcgnueabi/sysroot/usr/

cd /home/Jokiv/Documents/dir-890l/GPL-890L
. setupenv

#sudo aptitude install autoconf

#cd ${PROJECTDIR}libs
#rm -rf automake-1.14.1/
##wget http://ftp.gnu.org/gnu/automake/automake-1.14.1.tar.gz
#tar -zxvf automake-1.14.1.tar.gz
#cd automake-1.14.1
#./configure
#make 
#make install

#sleep 3

# build OpenSSL
#echo "!!!!!!!!!!!!!!!"
#echo " BUILD OpenSSL"
#echo "!!!!!!!!!!!!!!!"
#cd ${PROJECTDIR}libs/
#tar -zxvf openssl-1.0.2l.tar.gz
#cd ${SSL_PATH}
#mkdir -p ${SSL_PATH}install/
#make clean

#./Configure -DOPENSSL_NO_HEARTBEATS --openssldir=${SSL_PATH}install shared os/compiler:${TARGETMACH}- --prefix=${SSL_PATH}install -fPIC

#make
#make install
#cd install/lib/
#$AR -x libcrypto.a
#$CC -shared *.o -o libcrypto.so
#rm *.o
#$AR -x libssl.a
#$CC -shared *.o -o libssl.so
#rm *.o

#sleep 3

# build libconfig
echo "!!!!!!!!!!!!!!!"
echo "BUILD LibConfig"
echo "!!!!!!!!!!!!!!!"

#sudo apt-get install texinfo

cd ${LIBCONFIG_PATH}
make clean
rm -rf ${LIBCONFIG_PATH}install/
mkdir -p ${LIBCONFIG_PATH}install

./configure --prefix=${LIBCONFIG_PATH}install/ --host=${TARGETMACH} --build=${BUILDMACH} CC=${CC}

make
make install

sleep 3

# build libevent
echo "!!!!!!!!!!!!!!!!"
echo " BUILD LibEvent"
echo "!!!!!!!!!!!!!!!!"

cd ${LIBEVENT_PATH}
make clean
mkdir -p ${LIBEVENT_PATH}install
rm -rf ${LIBEVENT_PATH}install/*

./configure --host=${TARGETMACH} --build=${BUILDMACH} CC=${CC} --prefix=${LIBEVENT_PATH}install LDFLAGS=-L${SYSTEM_LIBS}lib CFLAGS=-I${SYSTEM_LIBS}include/
#./configure --host=${TARGETMACH} --build=${BUILDMACH} CC=${CC} --prefix=${LIBEVENT_PATH}install LDFLAGS=-L${SSL_PATH}install/lib CFLAGS=-I${SSL_PATH}install/include/
make 
make install

sleep 3

# build embediProxy
echo "!!!!!!!!!!!!!!!!!!!"
echo " BUILD embediProxy"
echo "!!!!!!!!!!!!!!!!!!!"

cd ${PROJECTDIR}
make clean
make ARCH_LIBEVENT_PATH=${LIBEVENT_PATH}install/lib/ INCLUDE_LIBEVENT_PATH=${LIBEVENT_PATH}install/include/ ARCH_LIBCONFIG_PATH=${LIBCONFIG_PATH}install/lib/ INCLUDE_LIBCONFIG_PATH=${LIBCONFIG_PATH}install/include/ INCLUDE_SSL_PATH=${SYSTEM_LIBS}include/ LIBS_SSL_PATH=${SYSTEM_LIBS}lib/ ARCH_LIBC_PATH=${SYSTEM_LIBS}lib/ CC=${CC}

sleep 3

# copy libs and binaries to final dir
echo "!!!!!!!!!!!!!!!!!!!!!!!!"
echo " COPY binaries and libs "
echo "!!!!!!!!!!!!!!!!!!!!!!!!"

cd ${PROJECTDIR}../
rm -rf embediProxy_DLINK_${CROSS}/
mkdir -p embediProxy_DLINK_${CROSS}
#mkdir -p embediProxy_DLINK_${CROSS}/libs/
#mkdir -p embediProxy_${CROSS}/libs/openssl
#cp -r ${SSL_PATH}install/* embediProxy_${CROSS}/libs/openssl
cp ${PROJECTDIR}embediProxy embediProxy_DLINK_${CROSS}/
${STRIP} embediProxy_DLINK_${CROSS}/embediProxy
tar -zcvf embediProxy_DLINK_${CROSS}.tar.gz embediProxy_DLINK_${CROSS}/





