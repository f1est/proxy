
CFLAGS 		= -DNDEBUG --std=c11 -D_BSD_SOURCE #-Wall 
CC 		=gcc
CXX 		=g++

SOURCES 	=$(wildcard *.c)
ARCHS 		=/home/boris/projects/libs/libevent/install/lib/libevent_openssl.a /home/boris/projects/libs/libevent/install/lib/libevent.a
LIBS 		=-lssl -lcrypto -lconfig #-lpthread 
INCLUDES 	=-I /home/boris/projects/libs/libevent/ -I /home/boris/projects/libs/libevent/install/include/ 
OBJS 		=$(SOURCES:.c=.o)
PROXY 	=proxy

all:  $(PROXY)

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

proxy:
$(PROXY):$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(ARCHS) $(INCLUDES) -o $@ $(LIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

.PHONY: clean

clean: 
	rm -f *.o
	rm proxy
