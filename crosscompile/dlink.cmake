SET(TARGETMACH arm-brcm-linux-uclibcgnueabi)
SET(BUILDMACH i686-pc-linux-gnu)
SET(TOOLSDIR /opt/hndtools-arm-linux-2.6.36-uclibc-4.5.3)
SET(FIND_ROOT_PATH /opt/hndtools-arm-linux-2.6.36-uclibc-4.5.3/arm-brcm-linux-uclibcgnueabi/sysroot/usr)

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

