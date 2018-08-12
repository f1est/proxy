#!/bin/bash
export DEBUG=debug
export PROJECTDIR=/home/jokiv/projects/le-EmbediProxy/
export TOOLSDIR=/home/jokiv/Documents/netgear_new/R7800-V1.0.2.32_gpl_src.tar.bz2/R7800-V1.0.2.32_gpl_src/staging_dir/toolchain-arm_v7-a_gcc-4.6-linaro_uClibc-0.9.33.2_eabi/
#export TARGETMACH=arm-none-linux-gnueabi
export BUILDMACH=i686-pc-linux-gnu
export CROSS=arm-openwrt-linux-uclibcgnueabi
export TARGETMACH=${CROSS}

export STAGING_DIR=${TOOLSDIR}
export PATH=${TOOLSDIR}bin:$PATH
export CC=${CROSS}-gcc
export LD=${CROSS}-ld
export AS=${CROSS}-as
export AR=${CROSS}-ar
export STRIP=${CROSS}-strip

export SSL_PATH=${PROJECTDIR}libs/openssl-1.0.2l/
export LIBCONFIG_PATH=${PROJECTDIR}libs/libconfig/
export LIBEVENT_PATH=${PROJECTDIR}libs/libevent/
export SYSTEM_LIBS=/home/jokiv/Documents/netgear_new/R7800-V1.0.2.32_gpl_src.tar.bz2/R7800-V1.0.2.32_gpl_src/staging_dir/target-arm_v7-a_uClibc-0.9.33.2_eabi/usr/

#sudo aptitude install autoconf
#sudo apt-get install texinfo

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


cd ${LIBCONFIG_PATH}
make clean
mkdir -p ${LIBCONFIG_PATH}install
rm -rf ${LIBCONFIG_PATH}install/*

./configure --prefix=${LIBCONFIG_PATH}install --host=${TARGETMACH} --build=${BUILDMACH} CC=${CC}

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
make ${DEBUG} ARCH_LIBEVENT_PATH=${LIBEVENT_PATH}install/lib/ INCLUDE_LIBEVENT_PATH=${LIBEVENT_PATH}install/include/ ARCH_LIBCONFIG_PATH=${LIBCONFIG_PATH}install/lib/ INCLUDE_LIBCONFIG_PATH=${LIBCONFIG_PATH}install/include/ INCLUDE_SSL_PATH=${SYSTEM_LIBS}include/ LIBS_SSL_PATH=${SYSTEM_LIBS}lib/ ARCH_LIBC_PATH=${TOOLSDIR}lib/ CC=${CC}

sleep 3

# copy libs and binaries to final dir
echo "!!!!!!!!!!!!!!!!!!!!!!!!"
echo " COPY binaries and libs "
echo "!!!!!!!!!!!!!!!!!!!!!!!!"

cd ${PROJECTDIR}../
rm -rf embediProxy_NETGEAR_/
mkdir -p embediProxy_NETGEAR_
#mkdir -p embediProxy_NETGEAR_${CROSS}/libs/
#mkdir -p embediProxy_NETGEAR_${CROSS}/libs/openssl
#cp -r ${SSL_PATH}install/* embediProxy_NETGEAR_${CROSS}/libs/openssl
cp ${PROJECTDIR}embediProxy embediProxy_NETGEAR_/embediProxy_${DEBUG}
${STRIP} embediProxy_NETGEAR_/embediProxy_${DEBUG}
#tar -zcvf embediProxy_NETGEAR_${CROSS}.tar.gz embediProxy_NETGEAR_${CROSS}/





