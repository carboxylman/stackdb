
------------
| OVERVIEW |
------------

This is a simple system call tracer for Linux kernels running in Xen
VMs.  It is not informed by debuginfo, so what it essentially does is
read a System.map file that corresponds to the kernel running the VM
you're going to probe, and grabs the addresses of each symbol it needs
(i.e., the entry points of each function you request to trace, and some
kernel variables it needs internally).  It pauses the VM, inserts
breakpoints at the requested locations, sets up internal breakpoint
handling mechanisms, and unpauses the VM.  Each time one of the
breakpoint instructions is hit (and Xen pauses the domain and notifies
the tracer), the tracer maps portions of the VM's memory into dom0 so it
can read the VM's memory---with the ultimate goal of providing the user
with information about the process that invoked the syscall, the current
process hierarchy, and the syscall's arguments.  It allows the user to
filter syscalls based on argument values (for the arguments it has type
info for, at least), and to take actions, such as aborting a syscall
with a return value prior to any work being done, or reporting it as a
monitored event to A3 monitors. It also now allows stopping after a
syscall has been executed, and can dump the return value and arguments
that it knows are "out" params. It also allows filtering on those
fields.

The tracer cannot trace all syscalls, because the syscall list is
hardcoded in -- and argument type info is only present for some syscalls
in the list (fully specifying it was too much busy work).  Also, When
this example/hack was first written, it was intended to be a quick piece
of demo-ware.  Now it's grown a little bit, but this is essentially a
prototype of our forthcoming, well-designed debuginfo-enabled VMI
architecture.  We will eventually replace this example with a complete
version that does not have, for instance, the syscall names, arguments,
and type info hardcoded.

Also, when first written, all arguments were passed on the command line,
including lists of syscalls to trace and filters to apply.  Some of
these command line params can now be specified in a configuration file,
which may be reloaded into the tracer by signaling it.

The syscall tracer allows you to specify a list (or wildcard to trace
all) of syscalls the tracer knows about, to "trace"---meaning that it
will insert breakpoints at those function entry points on your behalf,
decode process state and syscall arguments, and write them to a logfile,
and potentially report the breakpoint event to A3 infrastructure, or
abort the syscall with a user-provided value.

-----------
| SIGNALS |
-----------

The user may also signal the tracer with USR1 or USR2.  A USR1 flips the
"global action filter" bit.  This bit starts as enabled, so any action
filter specified by the user is applied.  If it is flipped with a USR1
signal to the tracer process, filter actions will not occur, and the a3
monitor will be sent a VMI event of type "would-abort".  Otherwise, the
monitor will see an event of type "abort".

A USR2 event will reload the tracer's config file, remove all existing
probes, filters, and actions, and replace them with new ones consistent
with the updated configuration.

-------------
| ARGUMENTS |
-------------
-c <configfile>  Path to the config file.
-a               Send a3 events (default is not to send unless this
                 option is specified).
-w <server:port> Specify the location of the A3 event server
-u <url string>  Specify the post URL of the A3 event server
-d               Enable vmprobes debug output (multiple d's increase the level).
-x               Enable xenaccess debug output (multiples increase).
-m <sysmap file> The path to the Sysmap file matching the VM kernel.

-s, -f -- deprecated and replaced by config file directives.

-----------------
| CONFIG SYNTAX |
-----------------

The config file can have multiple lines, and multiple invocations of
each 

Functions <function_name1>,<function_name2>,...

This line specifies a list of functions (from the set of functions the
tracer knows about) that the tracer should trace.  If you don't specify
this line, all functions the tracer knows about will be traced.  This is
not the complete set of syscalls, but it covers many of the imporant
ones.  Again, the details of decoding all syscall arguments have not
been implemented; we did the ones that seem to matter.  Further decoding
will be provided by debuginfo-enhanced VMI, so that it happens
"natively", without special hardcoded argument type knowledge.  You can
have as many Functions lines as you like.

ProcessListNames

Each time a syscall from the set
(sys_execve,sys_waitpid,sys_fork,sys_vfork,sys_clone) is traced, we
report a process list VMI event to the A3 monitor (of type=pslist).  By
specifying a comma-separated list of process names to this directive,
you can restrict the event contents to contain only processes whose
names match a name in this directive.  Otherwise, you'll receive a list
of all processes.  Here's an example of an A3 pslist event's contents:

domain=a3-app type=pslist pid=0,ppid=0,name=swapper|pid=1,ppid=0,name=init|pid=2,ppid=0,name=migration/0|pid=3,ppid=0,name=ksoftirqd/0|pid=4,ppid=0,name=watchdog/0|pid=5,ppid=0,name=events/0|pid=6,ppid=0,name=khelper|pid=7,ppid=0,name=kthread|pid=9,ppid=0,name=xenwatch|pid=10,ppid=0,name=xenbus|pid=16,ppid=0,name=kblockd/0|pid=18,ppid=0,name=kseriod|pid=53,ppid=0,name=pdflush|pid=54,ppid=0,name=pdflush|pid=55,ppid=0,name=kswapd0|pid=56,ppid=0,name=aio/0|pid=662,ppid=0,name=kcryptd/0|pid=663,ppid=0,name=kmpathd/0|pid=664,ppid=0,name=kmirrord|pid=666,ppid=0,name=rpciod/0|pid=726,ppid=0,name=udevd|pid=1897,ppid=0,name=rpcbind|pid=1917,ppid=0,name=rpc.statd|pid=1947,ppid=0,name=ntpd|pid=1956,ppid=0,name=ntpd|pid=1959,ppid=0,name=rsyslogd|pid=1963,ppid=0,name=rklogd|pid=1972,ppid=0,name=dbus-daemon|pid=1991,ppid=0,name=sshd|pid=2001,ppid=0,name=crond|pid=2014,ppid=0,name=hald|pid=2015,ppid=0,name=hald-runner|pid=2041,ppid=0,name=login|pid=2042,ppid=0,name=mingetty|pid=2043,ppid=0,name=mingetty|pid=2044,ppid=0,name=mingetty|pid=2045,ppid=0,name=mingetty|pid=2046,ppid=0,name=mingetty|pid=2057,ppid=0,name=bash|pid=2108,ppid=0,name=tcsh|pid=2133,ppid=0,name=tcsh|

Filter

This is a rather complex directive.  You can have multiple Filter lines;
each line specifies a separate filter.  Each time one of the syscalls
you specified in the Functions list is traced, the list of filters is
checked against that syscall.  Only the first matching filter is applied
(it's like an iptables rule chain).  Filters are by now badly
named... but they allow you to

  * apply an "abort" return action to a syscall.  An abort allows you to
    specify a syscall's return code, and forces an immediately return
    from the syscall without executing its body.  Recall that flipping
    the global action filter bit will disable this from happening until
    you flip the bit back.  This is a convenience feature for demos.

  * simply "match" a traced function and report it back to the A3
    monitor.  All traced functions are logged to standard output, but
    only those that match a filter will be reported as A3 events.

The format of the Filter directive is basically a comma-separated list
of parameters; you need not specify them all!

  * function=(syscall_name|*) .  If *, it matches all functions.

  * argname=(arg_name|*) .  If you specify an argument name, you *must*
    have also specified a function name.  Otherwise, the filter could
    match any argument.  If you specify arg_name:decoding_name, instead
    of just arg_name, the value of argval will apply to the decoding of
    this arg, not the arg itself.

  * argval=(unix_regex|*) .  If *, it'll match anything.  Otherwise, the
    given regular expression is applied to a string decoding of the
    argument.  We do not decode all arguments to strings, again, for the
    same reason that hardcoding all type and decoding knowledge takes a
    long time and is simply busy work until we have debuginfo support.

  * when=(pre|post|both) .  Specifies when the syscall should be matched.
    You can match before ("pre"), after ("post") or both ("both").
    If "when" is not specified, the default is "pre" to be compatible
    with the old behavior.

  * pid=<process_id>.  Match on process id.

  * ppid=<parent_process_id> OR ppid=^<parent_process_id>.  This matches
    either the parent process id, or if you prepend ^, it will match any
    process who has parent_process_id as an ancestor at any level up in
    the process hierarchy.

  * uid, gid .  Match on UID or GID.

  * name=<process_name> OR name=^<process_name>.  This matches
    either the parent process name, or if you prepend ^, it will match any
    process who has parent_process_name as an ancestor at any level up in
    the process hierarchy.

  * retval=<return-code>.  If this is an abort filter, return this code
    from syscalls that match this filter.

  * retval=(unix_regex|*).  If this is a match filter, match the syscall
    return value against this value ala "argval". NOTE that in this use,
    you cannot also use argval= (due to a coding shortcut I took).

  * apply=(0|1).  If 1, this is an abort filter and it will be applied
    if the global action filter bit is set... and thus the the value
    of retval will be returned during a syscall abort.  If 0 (the
    default value for this param), it is simply a match filter.

Here's a couple examples:

Filter  function=sys_execve,name=php-cgi,apply=1,retval=-1

  * This filter would restrict any processes with a name of 'php-cgi'
    from exec'ing anything. Note that apply MUST appear befor retval
    to signal that this is an abort filter.

Filter  function=sys_waitpid,name=php-cgi,when=post,retval=^[1-9]

  * This filter matches returns from waitpid calls that returns an
    actual pid (i.e., not -1 or 0).

Filter function=do_exit,name=apache,argname=code:signal,argval=SEGV

  * This filter matches any executions of the (non-syscall!) kernel
    function do_exit (it's the only way we can catch process death) by
    an apache process that died due to a SEGV signal.  We match on the
    string decoding.  If you tried to match on just argname=code, for
    instance, you would have to match the full integer return code
    format to catch SEGV (and since multiple bits of info are in that
    return code, it is not trivial to filter based on the signal name
    that cauesd the process to die --- hence filtering on argname
    decodings, not just argnames themselves).

  * This filter would produce an A3 event like 

    VMI domain=a3-app type=match sys_execve(code=0xdeadbeef,code:signal=SIGSEGV,code:status=255))

Note -- name=^apache would match any process who has an ancestor pid named apache.  So, if an apache process spawned a sh, and your sh process exec'd nc, then if you had the following filter

Filter  function=sys_execve,argname=regs:filename,argval=/usr/bin/nc,name=^apache

  * This filter would match an attempt by php to exec nc via sh, because even
    though the sh process is not named apache, it still has a process
    named apache as an ancestor. 

Another thing, Aaron -- I recall you were interested in filtering connect syscalls too.  On linux, many socket syscalls are multiplexed through a single syscall, sys_socketcall (including connect).

You can get connects like this:

Filter  function=sys_socketcall,argname=call:call,argval=connect 

  * On linux, many socket syscalls are multiplexed through a single
    syscall, sys_socketcall (including connect).  You can get connects
    using the expression above.

The accept syscall is more useful to stop afterward, when the connection
has been made and the socket struct filled in. You can do that with:

Filter  function=sys_socketcall,argname=call:call,argval=accept,when=post

-------
| FAQ |
-------

Why do some exec calls show a "(null)" filename and first argument?

This is not a bug, as best we've been able to tell.  What's really going
on is that the underlying page the data is on is in a page that is not
paged in from disk.  This only happens for some invocations of execve --
I've only seen it happen for data that resides in, for instance, the
virtual address space of a program that contains libc -- so, a static
data buffer that has not yet been paged in by the kernel (lazy page-in
strategy for populating a new process's address space).  The reason this
makes sense for the examples below is that the first execve is libc
calling out to /bin/sh to execute 'id' -- and the string /bin/sh is
probably hard-coded into libc in a static data buffer.  Note how the
filenames are (null) too.

So it's a reasonable explanation, and that's why I've never investigated
this problem, although I've been aware of it for a long time.

We could do all the work to actually make sure this is a true
assessment, but it is not trivial.


