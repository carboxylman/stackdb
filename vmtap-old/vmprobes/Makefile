## -*- mode: Makefile -*-
##
## Copyright (c) 2011, 2012 The University of Utah
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License as
## published by the Free Software Foundation; either version 2 of
## the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.

###############################################################################

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
