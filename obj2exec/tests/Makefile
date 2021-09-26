# Path to custom linker
LINKER=../obj2exec

# List of tests
TESTS=test001 test002 test003 test004 test005 test006 test020 test021 test022 test023 test024

# Each program (test) only has 1 source code file
%.o: %.c syscall.inc test.h
	gcc -c -o $@ -fno-asynchronous-unwind-tables -nostdlib -static -I. $<

obj: $(patsubst %,%.o,${TESTS})

.PHONY: clean

clean:
	rm -f *.o *.link *.load *.ref 
