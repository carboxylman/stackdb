#!/usr/bin/env python
import sys
from vmtap import *

# global count for sys_open
count = 0

# this function is called before original execution.
def pre_handler():

	global count
	count += 1
	print "[%d] %s called in %s (domid: %d)" \
		% (count, symbol_name(), domain_name(), domain_id())
	
	filename = arg(0)
	flags = arg(1)
	mode = arg(2)
	print " -- filename: %08x (%s)" % (filename, read_path(filename))
	print " -- flags: %08x" % (flags)
	print " -- mode: %08x" % (mode)
	
	return 1

# this function is called after original execution.
def post_handler():
	if count == 10:
		return 0
	return 1

# register probe
res = register_vmtap("a3guest", "sys_open", pre_handler, post_handler)
if res == 0:
	print "failed to register probe"
	unregister_vmtap()
	sys.exit(1)
print "probe registered"

# wait until pre-handler or post-handler returns 0
loop_vmtap()

# unregister probe
unregister_vmtap()
print "probe unregistered"
