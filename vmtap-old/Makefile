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

CC= gcc
LD= ld
CFLAGS= -I/usr/include/python2.5
LFLAGS= -lvmprobes -lxenaccess -lxenctrl

SWIG= swig
SFLAGS= -python

TARGET= vmtap

PY= python

all: vmtap

vmtap: $(TARGET).i $(TARGET).c $(TARGET).h
	$(SWIG) $(SFLAGS) $(TARGET).i
	$(CC) -c $(TARGET).c $(TARGET)_wrap.c $(CFLAGS)
	$(LD) -shared $(TARGET).o $(TARGET)_wrap.o $(LFLAGS) -o _$(TARGET).so

clean:
	rm -f *.o
	rm -f *_wrap.c
	rm -f *.pyc
	rm -f _$(TARGET).so
	rm -f $(TARGET).py

test: test.py
	sudo $(PY) test.py
