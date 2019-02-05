CC = musl-gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -Werror -fPIC -g -I/usr/include -DOAUTHENV_DEBUG

all: liboauthenv.so

oauthenv.o: oauthenv.c sasl.h
liboauthenv.so: oauthenv.o
	$(CC) -shared -nostdlib -o $@ $<

objdump: liboauthenv.so
	objdump -TC $<

clean:
	rm -f oauthenv.o liboauthenv.so

.PHONY: clean objdump
