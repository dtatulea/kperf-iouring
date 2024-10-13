# SPDX-License-Identifier: BSD-3-Clause

CCAN_PATH := ./ccan

CC=gcc
CFLAGS=-std=gnu99   -I$(CCAN_PATH)   -I liburing/src/include   -O2   -W -Wall -Wextra -Wno-unused-parameter -Wshadow   -DDEBUG   -g

LIBS=-lm -L$(CCAN_PATH) -pthread -lccan -l:liburing.a -L liburing/src

include $(wildcard *.d)

all: server client units liburing/src/liburing.a
units: bipartite_match cpu_stat

server: $(CCAN_PATH)/libccan.a liburing/src/liburing.a server.o server_session.o proto.o worker.o cpu_stat.o tcp.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

client: $(CCAN_PATH)/libccan.a liburing/src/liburing.a client.o proto.o bipartite_match.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(CCAN_PATH)/libccan.a:
	make -C $(CCAN_PATH)/
	ar rcs $(CCAN_PATH)/libccan.a $(CCAN_PATH)/ccan/*/*.o

liburing/src/liburing.a:
	make -C liburing library
$(OBJECTS): submodule_liburing

clean:
	rm -rf *.o *.d *~ bipartite_match cpu_stat

distclean:
	rm -rf *.o *.d *~ bipartite_match cpu_stat server client $(CCAN_PATH)/libccan.a

bipartite_match: $(CCAN_PATH)/libccan.a
	$(CC) $(CFLAGS) -DKPERF_UNITS bipartite_match.c -o bipartite_match $(CCAN_PATH)/libccan.a

cpu_stat: $(CCAN_PATH)/libccan.a
	$(CC) $(CFLAGS) -DKPERF_UNITS cpu_stat.c -o cpu_stat $(CCAN_PATH)/libccan.a

%.o: %.c
	$(COMPILE.c) -MMD -o $@ $<

.PHONY: all clean units ccan distclean submodule_liburing
.DEFAULT_GOAL=all
