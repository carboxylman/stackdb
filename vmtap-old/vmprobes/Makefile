# File:   Makefile
# Author: Chung Hwan Kim
# E-mail: chunghwn@cs.utah.edu

CC=gcc
AR=ar

CFLAGS=-fPIC
CFLAGS+=-I../
#CFLAGS+=-D_VERBOSE

LFLAGS=-shared

OBJECTS=vmprobes.o
OBJECTS+=arch/i386/vmprobes.o
SHARED=libvmprobes.so
STATIC=libvmprobes.a

HEADERS=vmprobes.h
ARCH=arch/i386
INCLUDE=/usr/local/include/vmprobes
LIB=/usr/local/lib

all: $(SHARED) $(STATIC)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<
	
$(SHARED): $(OBJECTS)
	$(CC) $(CFLAGS) $(LFLAGS) $(OBJECTS) -o $@

$(STATIC): $(OBJECTS)
	$(AR) rcs $(STATIC) $(OBJECTS)

clean: 
	rm -f $(SHARED) $(STATIC) $(OBJECTS)

install: $(SHARED) $(STATIC)
	mkdir -p $(INCLUDE) $(INCLUDE)/$(ARCH)
	cp $(HEADERS) $(INCLUDE)
	cp $(ARCH)/$(HEADERS) $(INCLUDE)/$(ARCH)
	cp $(SHARED) $(LIB)
	cp $(STATIC) $(LIB)

uninstall:
	rm -rf $(INCLUDE)
	rm -f $(LIB)/$(SHARED)
	rm -f $(LIB)/$(STATIC)
