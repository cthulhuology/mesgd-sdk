CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -I../3rd-party/cJSON -I../3rd-party/unity
LDFLAGS = -lssl -lcrypto

CJSON   = ../3rd-party/cJSON/cJSON.c
UNITY   = ../3rd-party/unity/unity.c

.PHONY: all test test-mesgd test-mesgd-ws clean

all: test_pki test_mesgd test_mesgd_ws

test_pki: test_pki.c $(CJSON) $(UNITY)
	$(CC) $(CFLAGS) -o test_pki test_pki.c $(CJSON) $(UNITY) $(LDFLAGS)

test_mesgd: test_mesgd.c pki.c $(CJSON) $(UNITY)
	$(CC) $(CFLAGS) -o test_mesgd test_mesgd.c $(CJSON) $(UNITY) $(LDFLAGS)

test_mesgd_ws: test_mesgd_ws.c mesgd.c mesgd.h pki.c $(CJSON) $(UNITY)
	$(CC) $(CFLAGS) -o test_mesgd_ws test_mesgd_ws.c $(CJSON) $(UNITY) $(LDFLAGS) -lcurl

test: test_pki
	./test_pki

test-mesgd: test_mesgd
	./test_mesgd

test-mesgd-ws: test_mesgd_ws
	./test_mesgd_ws

clean:
	rm -f test_pki test_mesgd test_mesgd_ws
