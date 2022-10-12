CC = gcc
CFLAGS = -Wall -g -Og -pthread
LDFLAGS = -g -pthread

CFLAGS = -g -Og -Wall -pthread
SHELL = /bin/sh

all:	webserver

webget:	webget.c
	$(CC) $(CFLAGS) -o $@ $<

webserver: webserver.c
	$(CC) $(CFLAGS) -o $@ $<

handin:
	cs105submit webserver.c

clean:
	rm -f *~ *.o webserver server.log
