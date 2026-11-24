CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I../..
LDFLAGS = -lssl -lcrypto -lwebsockets -lcjson -lm

.PHONY: all clean

all: sample

sample: sample.c
	$(CC) $(CFLAGS) -o sample sample.c $(LDFLAGS)

clean:
	rm -f sample
