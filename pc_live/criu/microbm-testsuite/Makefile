all: bm bmcli
CC=gcc
CFLAGS=-g -lpthread
DEPS = common.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

bm: benchmark.o child.o
	gcc -o $@ $^ $(CFLAGS)
bmcli: command.o
	gcc -o $@ $^ $(CFLAGS)
clean:
	rm -f *.o bm bmcli
cleantxt:
	rm -f *.txt
