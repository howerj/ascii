CFLAGS=-Wall -Wextra -std=c99 -pedantic -fwrapv -O2
TARGET=ascii

.PHONY: default all run test clean

default all: ${TARGET}

run test: ${TARGET}
	./${TARGET}

clean:
	rm -f ${TARGET} *.exe *.o *.a
