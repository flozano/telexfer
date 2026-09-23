CC      ?= cc
CFLAGS  ?= -O2 -g
# 'override' keeps these when CFLAGS is given on the command line
# (e.g. make CFLAGS="-O1 -fsanitize=address")
override CFLAGS += -std=c11 -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L \
           -Wall -Wextra -Wshadow -Wno-unused-parameter
LDFLAGS ?=

LIB_SRCS = src/util.c src/ber.c src/trace.c src/x25.c src/tp0.c \
           src/session.c src/pres.c src/ftam_pdu.c
LIB_OBJS = $(LIB_SRCS:.c=.o)

all: ftam ftamd

ftam: $(LIB_OBJS) src/ftam.o src/main.o
	$(CC) $(LDFLAGS) -o $@ $^

# minimal FTAM responder used by the test suite
ftamd: $(LIB_OBJS) tests/ftamd.o
	$(CC) $(LDFLAGS) -o $@ $^

src/%.o: src/%.c src/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

tests/%.o: tests/%.c src/*.h
	$(CC) $(CFLAGS) -Isrc -c -o $@ $<

test: all
	./tests/run.sh

clean:
	rm -f ftam ftamd src/*.o tests/*.o

.PHONY: all test clean
