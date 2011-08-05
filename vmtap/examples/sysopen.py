#!/usr/bin/env python
import vmtap

count = 0

# User handler invoked by vmtap whenever the probe gets triggered
def on_sys_open(p):
    global count
    count += 1
    print "[%d] %s() called in %s" % (count, vmtap.symbol(p), vmtap.domain(p))

# Inject a probe by passing a probepoint expression and a callback handler
vmtap.probe("a3guest.kernel.function(sys_open).call", on_sys_open)

# Start trigerring all injected probes
# This function returns when "vmtap.stop()" is called or "ctrl+c" is pressed.
vmtap.run()

print "sys_open() called", count, "times"
