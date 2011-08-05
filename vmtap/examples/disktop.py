#!/usr/bin/env python
import vmtap

read_bytes = 0
write_bytes = 0

def on_vfs_read_call(p):
	global read_bytes
	read_bytes += vmtap.arg(p,2)
	print "%d called in %s" % (vmtap.symbol(p), vmtap.domain(p))

def on_vfs_write_return(p):
	global write_bytes
	write_bytes += vmtap.retval(p)
	print "%d called in %s" % (vmtap.symbol(p), vmtap.domain(p))

def on_time(p):
	if (read_bytes + write_bytes) > 0:
		print "Average:", ((read_bytes+write_bytes)/1024)/5, "Kb/sec"
		print "Read:", read_bytes/1024, "Kb"
		print "Write:", write_bytes/1024, "Kb"

vmtap.probe("a3guest.kernel.function(vfs_read).call", on_vfs_read_call)
vmtap.probe("a3guest.kernel.function(vfs_write).return", on_vfs_write_return)

vmtap.run()
