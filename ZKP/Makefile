CC = gcc
CFLAGS = -Wall -lzpie

all: client server

client: client.c
	$(CC) -o client client.c -lzpie

server: server.c
	$(CC) -o server server.c -lzpie

clean:
	rm -f client server
