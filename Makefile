
CC = gcc -g -O0 -W
LDFLAGS = -levent -ljansson
INSTALLDIR = /usr/local/lib
INCLUDEDIR = /usr/local/include

EXE := tinyproxy

OBJS = main.o \
client.o \
common.o \
dialog.o \
middleware.o \
opts.o \
server.o \
message.o \
util-log.o \
util-json.o

SOURCES = client.c client.h \
common.c common.h \
dialog.c dialog.h \
main.c \
middleware.c middleware.h \
opts.c opts.h \
server.c server.h \
message.c message.h \
util-log.c util-log.h \
util-mem.h \
util-str.h util-lock.h \
util-json.c util-json.h \
main.c


all: $(EXE)

$(EXE): $(OBJS) 
	$(CC) $(OBJS) -o $(EXE) $(LDFLAGS)

*.o:*.c

test: $(EXE)


install: $(EXE)
	cp $(EXE) $(INSTALLDIR) 

uninstall:
	rm -f $(INSTALLDIR)/$(EXE)
clean:
	rm -f  $(EXE) $(OBJS) test

.PHONY: all install clean test
