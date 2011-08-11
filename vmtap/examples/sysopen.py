#!/usr/bin/env python
import vmtap

count = 0

# User handler invoked by vmtap whenever the probe gets triggered
def on_sys_open(p):
    global count
    count += 1
    print "[%d] %s() called in %s" % (count, vmtap.symbol(p), vmtap.domain(p)) 
    print "  -- filename: %s" % (vmtap.arg_string(p,0))
    print "  -- flags: %08x" % (vmtap.arg(p,1))
    print "  -- mode: %08x" % (vmtap.arg(p,2))

# Inject a probe by passing a probepoint expression and a callback handler
success = vmtap.probe("a3guest.kernel.function(sys_open)", on_sys_open)

if success:
    print "probe injected"

    # Start trigerring all injected probes
    # This function returns when "vmtap.stop()" is called or "ctrl+c" is pressed
    vmtap.run()

    print "sys_open() called", count, "times"
