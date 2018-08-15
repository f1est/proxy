#!/bin/sh
cd build
export STAGING_DIR=/home/f1est/Documents/netgear_new/R7800-V1.0.2.32_gpl_src.tar.bz2/R7800-V1.0.2.32_gpl_src/staging_dir/toolchain-arm_v7-a_gcc-4.6-linaro_uClibc-0.9.33.2_eabi/
export PATH="/home/f1est/Documents/netgear_new/R7800-V1.0.2.32_gpl_src.tar.bz2/R7800-V1.0.2.32_gpl_src/staging_dir/toolchain-arm_v7-a_gcc-4.6-linaro_uClibc-0.9.33.2_eabi/bin:$PATH"
cmake -DCMAKE_TOOLCHAIN_FILE=../crosscompile/netgear.cmake ../
make
