# -*- mode: Makefile -*-
##
## Copyright (c) 2013-2014 The University of Utah
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

#######################################################################

obj-m := psaction_module.o
obj-m += repair_driver.o
obj-m += ps_deescalate_module.o
obj-m += system_map_reset.o
obj-m += killsocket_module.o
obj-m += close_file_module.o
obj-m += start_process_module.o
obj-m += sled_object_module.o
obj-m += trusted_load_module.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
ccflags-y := -g

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
