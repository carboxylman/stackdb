#!/usr/bin/env python
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
