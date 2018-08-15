cmake_minimum_required (VERSION 3.6)
set(PROJECT embeddedProxy)
project (${PROJECT})

# The version number.
set (${PROJECT}_VERSION_MAJOR 0)
set (${PROJECT}_VERSION_MINOR 0)

message("CMAKE_SOURCE_DIR = ${CMAKE_SOURCE_DIR}")
message("CMAKE_BINARY_DIR = ${CMAKE_BINARY_DIR}")

if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
        file(MAKE_DIRECTORY build)
        message(FATAL_ERROR "In-source builds are not allowed. Change directory to \"./build\"")
endif ()

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)


set(DEFAULT_CFLAGS "-D_BSD_SOURCE -Wall --std=c99") 

# check type of build
if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "")
        string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)
endif()
if(build_type STREQUAL "debug")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${DEFAULT_CFLAGS} -DDEBUG")
        message("CMAKE_C_FLAGS_DEBUG = ${CMAKE_C_FLAGS_DEBUG}")
elseif(build_type STREQUAL "addrsan") 
        option(LIBEVENTSAN "build libevent with sanitizer" OFF) # OFF is the default
        set(CMAKE_BUILD_TYPE addrsan) # clang address sanitizer
        set(CMAKE_C_COMPILER "clang")
        set(CMAKE_C_FLAGS "${DEFAULT_CFLAGS}")
        set(CMAKE_C_FLAGS_ADDRSAN "-DCLANG_SANITIZER -DDEBUG -g -fsanitize=address -fno-omit-frame-pointer -fsanitize-address-use-after-scope -fsanitize=leak")
        set(_CMAKE_TOOLCHAIN_PREFIX llvm-)
        message("CMAKE_C_FLAGS_ADDRSAN = ${CMAKE_C_FLAGS_ADDRSAN}")
elseif(build_type STREQUAL "memsan")
        option(LIBEVENTSAN "build libevent with sanitizer" OFF) # OFF is the default
        set(CMAKE_BUILD_TYPE memsan) #clang memory sanitizer
        set(CMAKE_C_COMPILER "clang")
        set(CMAKE_C_FLAGS "${DEFAULT_CFLAGS}")
        set(CMAKE_C_FLAGS_MEMSAN "-DDEBUG -g -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -fsanitize-memory-use-after-dtor")
        set(_CMAKE_TOOLCHAIN_PREFIX llvm-)
        message("CMAKE_C_FLAGS_MEMSAN = ${CMAKE_C_FLAGS_MEMSAN}")
elseif(build_type STREQUAL "undefsan")
        option(LIBEVENTSAN "build libevent with sanitizer" OFF) # OFF is the default
        set(CMAKE_BUILD_TYPE undefsan) #clang undefined behavior sanitizer
        set(CMAKE_C_COMPILER "clang")
        set(CMAKE_C_FLAGS "${DEFAULT_CFLAGS}")
        set(CMAKE_C_FLAGS_UNDEFSAN "-DDEBUG -g -fsanitize=undefined")
        message("CMAKE_C_FLAGS_UNDEFSAN = ${CMAKE_C_FLAGS_UNDEFSAN}")
        set(_CMAKE_TOOLCHAIN_PREFIX llvm-)
else()
        set(CMAKE_C_FLAGS "${DEFAULT_CFLAGS} -DNDEBUG")
endif()
message("CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")

#add_custom_target(debug COMMAND set(CMAKE_C_FLAGS "-DDEBUG -g --std=c99 -D_BSD_SOURCE") COMMENT "!!! build as debug !!!")
#message("CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")

if(LIBEVENTSAN)
        message("LIBEVENTSAN !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!    DCMAKE_SYSTEM_PROCESSOR = ${CMAKE_SYSTEM_PROCESSOR}")
endif()

include(ExternalProject)

# configure and install LibEvent

set(LIBEVENT_INSTALL_DIR ${CMAKE_BINARY_DIR}/install/libevent)
if(LIBEVENTSAN)
ExternalProject_Add(libevent_project
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/libs/libevent
        DOWNLOAD_COMMAND ""
        UPDATE_COMMAND ""
        CMAKE_ARGS 
                -DCMAKE_INSTALL_PREFIX=${LIBEVENT_INSTALL_DIR}
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                -D_CMAKE_TOOLCHAIN_PREFIX=${_CMAKE_TOOLCHAIN_PREFIX}
                -DCMAKE_C_FLAGS_ADDRSAN=${CMAKE_C_FLAGS_ADDRSAN}
                -DCMAKE_C_FLAGS_MEMSAN=${CMAKE_C_FLAGS_MEMSAN}
                -DCMAKE_C_FLAGS_UNDEFSAN=${CMAKE_C_FLAGS_UNDEFSAN}

#for crosscompile
                -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
                -DCMAKE_SYSTEM_VERSION=${CMAKE_SYSTEM_VERSION}
                -DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}
                -DCMAKE_FIND_ROOT_PATH=${CMAKE_FIND_ROOT_PATH}
                -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=${CMAKE_FIND_ROOT_PATH_MODE_PROGRAM}
                -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=${CMAKE_FIND_ROOT_PATH_MODE_LIBRARY}
                -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=${CMAKE_FIND_ROOT_PATH_MODE_INCLUDE}
        )
else()
ExternalProject_Add(libevent_project
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/libs/libevent
        DOWNLOAD_COMMAND ""
        UPDATE_COMMAND ""
        CMAKE_ARGS 
                -DCMAKE_INSTALL_PREFIX=${LIBEVENT_INSTALL_DIR}
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}

#for crosscompile
                -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
                -DCMAKE_SYSTEM_VERSION=${CMAKE_SYSTEM_VERSION}
                -DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}
                -DCMAKE_FIND_ROOT_PATH=${CMAKE_FIND_ROOT_PATH}
                -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=${CMAKE_FIND_ROOT_PATH_MODE_PROGRAM}
                -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=${CMAKE_FIND_ROOT_PATH_MODE_LIBRARY}
                -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=${CMAKE_FIND_ROOT_PATH_MODE_INCLUDE}
        )
endif()

add_library(libevent STATIC IMPORTED)
set_property(TARGET libevent PROPERTY IMPORTED_LOCATION ${LIBEVENT_INSTALL_DIR}/lib/libevent.a)
add_dependencies(libevent libevent_project)

add_library(libevent_ssl STATIC IMPORTED)
set_property(TARGET libevent_ssl PROPERTY IMPORTED_LOCATION ${LIBEVENT_INSTALL_DIR}/lib/libevent_openssl.a)
add_dependencies(libevent_ssl libevent_project)


# configure and install LibConfig

set(LIBCONFIG_INSTALL_DIR ${CMAKE_BINARY_DIR}/install/libconfig)
if(CMAKE_CROSSCOMPILING)
#        set(ENVPATH $ENV{PATH})
#        set(ENV{PATH} ${TOOLSDIR}/bin:${ENVPATH})
#        set(ENVPATH $ENV{PATH})

#        EXECUTE_PROCESS(COMMAND sh -c "export PATH=${ENVPATH}") 
#        add_custom_target(export_path COMMAND ${CMAKE_COMMAND} -E env "export  PATH=$ENV{PATH}")
#        add_custom_target(export_path COMMAND set(ENV{PATH} ${TOOLSDIR}/bin:${ENVPATH}))
#        add_custom_command(TARGET export_path COMMAND set(ENV{PATH} ${TOOLSDIR}/bin:${ENVPATH}))
        
#        set(file_sh ${CMAKE_CURRENT_BINARY_DIR}/export_path.sh)
#        file(WRITE ${file_sh} "#!/bin/sh\n")
#        file(APPEND ${file_sh} "export PATH=\"${ENVPATH}\"")
#        execute_process(COMMAND chmod a+x ${file_sh} RESULT_VARIABLE res)
#        add_custom_target(export_path COMMAND /bin/sh -c ${CMAKE_CURRENT_BINARY_DIR}/export_path.sh)
#        add_custom_target(export ALL DEPEND export_path)

        set(CONFIGURING ${CMAKE_SOURCE_DIR}/libs/libconfig/configure --host=${TARGETMACH} --build=${BUILDMACH} CC=${CMAKE_C_COMPILER} --prefix=${LIBCONFIG_INSTALL_DIR})
else()
        set(CONFIGURING ${CMAKE_SOURCE_DIR}/libs/libconfig/configure --prefix=${LIBCONFIG_INSTALL_DIR})
endif()

ExternalProject_Add(libconfig_project
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/libs/libconfig
        DOWNLOAD_COMMAND ""
        PATCH_COMMAND ""
        INSTALL_DIR ${LIBCONFIG_INSTALL_DIR}
        UPDATE_COMMAND ""
        CONFIGURE_COMMAND ${CONFIGURING}
        )

add_library(libconfig STATIC IMPORTED)
set_property(TARGET libconfig PROPERTY IMPORTED_LOCATION ${LIBCONFIG_INSTALL_DIR}/lib/libconfig.a)
add_dependencies(libconfig libconfig_project)

set (LIBRARIES libconfig libevent libevent_ssl)

find_package(OpenSSL REQUIRED)

set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} )

include_directories(${LIBCONFIG_INSTALL_DIR}/include ${LIBEVENT_INSTALL_DIR}/include ${CMAKE_FIND_ROOT_PATH}/include)
file(GLOB SOURCES src/*.c)

add_executable(${PROJECT} ${SOURCES})
target_link_libraries (${PROJECT} ${LIBRARIES} ${OPENSSL_LIBRARIES})
