CFLAGS = -Wall -Wextra -pedantic

all: strace-light

syscalls.c syscalls.h:
	list_syscalls/list_syscalls.py -s linux,man -f c

strace-light.o: syscalls.h

strace-light: strace-light.o syscalls.o

test/true-light: ASFLAGS += -nostdlib
