CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -I../3rd-party/cJSON -I../3rd-party/unity
LDFLAGS = -lssl -lcrypto

CJSON   = ../3rd-party/cJSON/cJSON.c
UNITY   = ../3rd-party/unity/unity.c

.PHONY: all test clean

all: test_pki

test_pki: test_pki.c $(CJSON) $(UNITY)
	$(CC) $(CFLAGS) -o test_pki test_pki.c $(CJSON) $(UNITY) $(LDFLAGS)

test: test_pki
	./test_pki

clean:
	rm -f test_pki
