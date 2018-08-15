SET(TARGETMACH arm-openwrt-linux-uclibcgnueabi)
SET(BUILDMACH i686-pc-linux-gnu)
SET(TOOLSDIR /home/f1est/Documents/netgear_new/R7800-V1.0.2.32_gpl_src.tar.bz2/R7800-V1.0.2.32_gpl_src/staging_dir/toolchain-arm_v7-a_gcc-4.6-linaro_uClibc-0.9.33.2_eabi)
SET(FIND_ROOT_PATH /home/f1est/Documents/netgear_new/R7800-V1.0.2.32_gpl_src.tar.bz2/R7800-V1.0.2.32_gpl_src/staging_dir/target-arm_v7-a_uClibc-0.9.33.2_eabi/usr )

# this one is important
SET(CMAKE_SYSTEM_NAME Linux)

#this one not so much
SET(CMAKE_SYSTEM_VERSION 1)
SET(CMAKE_SYSTEM_PROCESSOR arm)

# specify the cross compiler
SET(CMAKE_C_COMPILER   ${TOOLSDIR}/bin/${TARGETMACH}-gcc)

# where is the target environment 

SET(CMAKE_FIND_ROOT_PATH ${FIND_ROOT_PATH}) 

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

