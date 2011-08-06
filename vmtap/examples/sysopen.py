#!/usr/bin/env python
import vmtap

count = 0

# User handler invoked by vmtap whenever the probe gets triggered
def on_sys_open(p):
    global count
    count += 1
    print "[%d] %s() called in %s" % (count, vmtap.symbol(p), vmtap.domain(p))
    print "- char: %c" % (vmtap.read_char(p, vmtap.address(p)))
    print "- int: %d" % (vmtap.read_int(p, vmtap.address(p)))
    print "- long: %ld" % (vmtap.read_long(p, vmtap.address(p)))
    print "- float: %f" % (vmtap.read_float(p, vmtap.address(p)))
    print "- double: %f" % (vmtap.read_double(p, vmtap.address(p)))

# Inject a probe by passing a probepoint expression and a callback handler
vmtap.probe("a3guest.kernel.function(sys_open).call", on_sys_open)

# Start trigerring all injected probes
# This function returns when "vmtap.stop()" is called or "ctrl+c" is pressed.
vmtap.run()

print "sys_open() called", count, "times"
