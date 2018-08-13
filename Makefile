CFLAGS 		= -DNDEBUG -D_BSD_SOURCE #-Wall --std=c11 
CC 		=gcc
CXX 		=g++

ARCH_LIBEVENT_PATH 	=/home/boris/projects/EMBEDDED/le-EmbeddedProxy/libs/libevent/install/lib/
INCLUDE_LIBEVENT_PATH 	=/home/boris/projects/EMBEDDED/le-EmbeddedProxy/libs/libevent/install/include/
ARCH_LIBCONFIG_PATH     =/home/boris/projects/EMBEDDED/le-EmbeddedProxy/libs/libconfig/install/lib/
INCLUDE_LIBCONFIG_PATH  =/home/boris/projects/EMBEDDED/le-EmbeddedProxy/libs/libconfig/install/include/

SOURCES 	=$(wildcard *.c)
ARCHS 		=$(ARCH_LIBEVENT_PATH)libevent_openssl.a $(ARCH_LIBEVENT_PATH)libevent.a $(ARCH_LIBCONFIG_PATH)libconfig.a
LIBS 		=-lssl -lcrypto # -lconfig #-lpthread 
INCLUDES 	=-I$(INCLUDE_LIBCONFIG_PATH) -I$(INCLUDE_LIBEVENT_PATH)
OBJS 		=$(SOURCES:.c=.o)
EMBEDDEDPROXY 	=embeddedProxy

all:  $(EMBEDDEDPROXY)

clang-address: CC 	=/home/boris/projects/LLVM/llvm-5.0.0/install/bin/clang
clang-address: CFLAGS 	= -DCLANG_SANITIZER -DDEBUG -g -fsanitize=address -fno-omit-frame-pointer -fsanitize-address-use-after-scope -fsanitize=leak --std=c11 -D_BSD_SOURCE
clang-address: all

clang-memory: CC 	=/home/boris/projects/LLVM/llvm-5.0.0/install/bin/clang
clang-memory: CFLAGS 	= -DDEBUG -g -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -fsanitize-memory-use-after-dtor --std=c11 -D_BSD_SOURCE
clang-memory: all

clang-undef: CC 	=/home/boris/projects/LLVM/llvm-5.0.0/install/bin/clang
clang-undef: CFLAGS 	= -DDEBUG -g -fsanitize=undefined --std=c11 -D_BSD_SOURCE
clang-undef: all

debug: CFLAGS 	= -DDEBUG -g --std=c11 -D_BSD_SOURCE
debug: all

embeddedProxy:
$(EMBEDDEDPROXY):$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(ARCHS) $(INCLUDES) -o $@ $(LIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

.PHONY: clean

clean: 
	rm -f *.o
	rm embeddedProxy
