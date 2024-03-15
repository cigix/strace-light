CFLAGS = -Wall -Wextra -pedantic

all: strace-light

test/true-light: ASFLAGS += -nostdlib
