CFLAGS=-Wall -Wextra -std=c99 -pedantic -fwrapv -O2
TARGET=ascii

.PHONY: default all run test tests clean

default all: ${TARGET}

run test tests: ${TARGET}
	./${TARGET} tests

clean:
	rm -f ${TARGET} *.exe *.o *.a
