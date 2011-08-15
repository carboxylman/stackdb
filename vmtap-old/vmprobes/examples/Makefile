# File:   examples/Makefile
# Author: Chung Hwan Kim
# E-mail: chunghwn@cs.utah.edu

CC=gcc

CFLAGS=-fPIC

LFLAGS=-lvmprobes
LFLAGS+=-lxenaccess
LFLAGS+=-lxenctrl

OBJECTS=vmprobebio.o
TARGET=vmprobebio

all: $(TARGET)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<
	
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LFLAGS) $(OBJECTS) -o $@
	
run: $(TARGET)
	sudo ./$(TARGET)
	
clean: 
	rm -f $(TARGET) $(OBJECTS)
