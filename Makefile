
CC = gcc -g -O0
LDFLAGS = -levent
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
util-log.o \
util-mem.o

SOURCES = client.c client.h \
common.c common.h \
dialog.c dialog.h \
main.c \
middleware.c middleware.h \
opts.c opts.h \
server.c server.h \
util-log.c util-log.h \
util-mem.c util-mem.h \
util-str.h util-lock.h \
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
