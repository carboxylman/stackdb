#!/usr/bin/env python
import vmtap, signal

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

def on_time(signum, frame):
    total_bytes = read_bytes + write_bytes
    if total_bytes > 0:
        print "Average:", (total_bytes/1024)/5, "Kb/sec"
        print "Read:", read_bytes/1024, "Kb"
        print "Write:", write_bytes/1024, "Kb"
    signal.alarm(1)

signal.signal(signal.SIGALRM, on_time)
success = vmtap.probe("a3guest.kernel.function(vfs_read)", on_vfs_read)
success = vmtap.probe("a3guest.kernel.function(vfs_write)", on_vfs_write)

if success:
    print "probes injected"

    signal.alarm(1)
    vmtap.run()
    print "probes removed"

    signal.alarm(0)
