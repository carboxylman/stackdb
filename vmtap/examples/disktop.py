#!/usr/bin/env python
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

import vmtap, vmtap_timer

read_bytes = 0
write_bytes = 0

def on_vfs_read(p):
    global read_bytes
    bytes = vmtap.arg(p,2)
    read_bytes += bytes

def on_vfs_write(p):
    global read_bytes
    bytes = vmtap.arg(p,2)
    write_bytes += bytes

def on_time():
    print "on_time() called"
    total_bytes = read_bytes + write_bytes
    if total_bytes > 0:
        print "Average:", (total_bytes/1024)/5, "Kb/sec"
        print "Read:", read_bytes/1024, "Kb"
        print "Write:", write_bytes/1024, "Kb"

timer = vmtap_timer.Timer(1.0, on_time)
success = vmtap.probe("a3guest.kernel.function(vfs_read)", on_vfs_read)
success = vmtap.probe("a3guest.kernel.function(vfs_write)", on_vfs_write)

if success:
    print "probes injected"

    timer.start()

    vmtap.run()
    print "probes removed"

    timer.cancel()
