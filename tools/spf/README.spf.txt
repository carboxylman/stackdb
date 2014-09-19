## -*- mode: Text -*-
##
## Copyright (c) 2013, 2014 The University of Utah
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


"Be sure to apply extra SPF."


------------
| OVERVIEW |
------------

spf (Symbol Probing Filter) probes symbols and runs various actions when
a filter matches.  It is similar to vmprobegeneric, but more featureful.

You attach spf to a target using the standard target arguments, plus any
backend-specific arguments.  Get the list of supported arguments for
your build by doing

  $ spf --help

You can supply simple probe filters on the command line; or you can
specify more complex and powerful ones in a config file (-C option).

You can reconfigure the set of filters specified in the config file
during runtime by updating the config file as desired, and signalling
spf with HUP or USR2.

-----------------
| CONFIG SYNTAX |
-----------------

The config file can have multiple lines.  Comments at the beginning of
lines are allowed; the comment character is '#' as usual.  Lines may be
blank.

At this point, only one directive is supported.


ProbeFilter <symbol_name> [id(<probeFilterId>)] [when(pre|post)] [disable()]  \
    [vfilter(value1=/regex/,value2=/regex/,...)]                              \
    [print()] [bt([<target_id>[,<thread_name_or_id>]])]                       \
    [signal(<target_id>,<thread_name_or_id>,<signo_or_name>)]                \]
    [report(rt=i|f,tn=<typename>,tid=<typeid>,rv=<resultvalue>,msg="<msg>",   \
            ttctx=all|hier|self|none),bt=0|1)]                                \
    [enable(<probeFilterId>)] [disable(<probeFilterId>)] [remove(<probeFilterId>)] \
    [abort(<returncode>)] [exit(<exitcode)]

This line places a probe on the symbol you supply.  If you provide a
function, spf will place a function entry/exit probe on it (i.e., if
your filter is a when(pre) filter, the filter expression will be checked
when the function is being entered; if your filter is a when(post)
filter, the expression will be checked when the function is being
exited); if you provide a variable (and if your target backend supports
hardware watchpoints, a watchpoint will be placed); if your target is an
OS and supports the OS personality interface, and if your symbol is a
syscall, a special syscall entry/exit probe will be placed (syscalls can
be special and funky, so we support probing them specifically).

The options and actions are described as follows.  Some may be used
multiple times; others only once; that is described by the {n} following
the syntax.

  id(<probeFilterId>) {1}

    <probeFilterId> is a C-conformant identifier for this filter.  You
    can only enable, disable, and remove filters that you provide
    identifiers for.  Obviously, this identifier must be unique!

  disable() {1}

    The filter starts life disabled; it will not be checked until it is
    enabled via the enable() option.

  when(pre|post) {1}

    When is the filter applied -- during the symbol probe's prehandling
    or posthandling stage.

  vfilter(<valuename1>=/<regex1>/,...) {1}

    Each filter filters the values of the underlying symbol probe.  If
    the probe is a function, you can filter on its arguments if
    when(pre), or on its return value (via the special name __RETURN__)
    if when(post).  <regex1> must be a UNIX regular expression (we
    enable REG_EXTENDED; see `man regex'.  All <valuename>=/<regex>/
    pairs must match; the filter is an AND filter.

  tfilter(<ctxtname1>=/<regex1>/,...) {1}

    Each tfilter filters against the context of the thread the probe was
    triggered within.  For now, there are several basic <ctxtname> names
    you can filter on.  By default, the target library supports

    tid      The thread id
    ptid     The thread's parent thread id (-1 if target does not support
             thread parents)
    tgid     The thread's group id (-1 if target does not support
             thread groups) (on Linux, the thread group id the process id)
    tidhier  A common-separated list of tids starting with the
             current tid, and then moving up the hierarchy to the root.
    name     The thread's name (the empty string if the target does not
             support thread names)
    namehier A comma-separated list of tid names starting with the
             current tid, and then moving up the hierarchy to the root.
    uid      The thread's uid (-1 if the target does not support thread
             parents)
    gid      The thread's gid (-1 if the target does not support thread
             parents)

(The remaining arguments act more like actions/commands than options.)

  print([ttctx=all|hier|self|none],[ttdetail=<-2|-1|0|1|2>]) {1}

    Writes a simple message about the probe and its values to standard
    output.  For instance, you might see

      sys_open (flags = 0,filename = /etc/ld.so.cache,mode = 1) = 3

    We also can print thread context information (i.e., id, name,
    parent id, uid, gid; or other target backend-specific values --
    i.e. registers, thread metadata, etc).  You can control how much
    detail and for which threads it's reported.  If ttdetail is not set,
    it defaults to 0.  ttdetail==-2 means print only tid; -1 means print
    only tid and name; 0 means print tid, name, ptid, uid, gid, and the
    0-th level of information from the target backend.  Anything greater
    than 0 increases the amount of data the backend will produce.  Then,
    you can also select which threads are printed via the ttctx field.
    If ttctx==all, all known threads will be displayed.  If ttctx==self,
    only the thread that triggered the probe will be displayed.  If
    ttctx==hier, then the thread hierarchy starting with the thread that
    triggered the probe, to its root parent, will be displayed.  If
    ttctx==none, no threads will be displayed.  The default is none.

  bt([<target_id>[,<thread_name_or_id>]])

    This command prints one or more backtraces of target threads to
    stdout.  If you don't specify <target_id> (or specify '-1'), it will
    print backtraces for the thread that is currently executing (i.e.,
    the one that hit the probe); otherwise, the target you specified
    will be used.  If you don't specify <thread_name_or_id>, it will
    print out the current thread.  If you use the value '0', it will
    print out all threads in the target.  If you specify a thread name,
    it will print out all threads for which
    strcmp(<thread_name_or_id>,thread->name) matches.  If you specify a
    thread number, it will print out that thread -- if it exists.

  signal(<target_id>,<thread_name_or_id>,<signo_or_signame>)

    This command injects a signal into a thread in an OS.
    If you specify -1 for <target_id> instead of a target id, it will
    signal a thread in the target that is currently executing (i.e.,
    the one that hit the probe); otherwise, the target you specified
    will be used.  If you don't specify <thread_name_or_id>, it will
    signal the current thread.  If you use the value '0', it will
    signal all threads in the target.  If you specify a thread name,
    it will signal all threads for which
    strcmp(<thread_name_or_id>,thread->name) matches.  If you specify a
    thread number, it will signal that thread -- if it exists.
    <signo_or_signame> is a signal number or signal name (i.e., SIGKILL,
    SIGINT, etc).

  report(rt=i|f,tn=<typename>,tid=<typeid>,rv=<resultvalue>,msg="<msg>",   \
         ttctx=all|hier|self|none),ttdetail=<-2|-1|0|1|2>,bt=0|1) {1}

    This is designed to allow spf to be used as an Analysis run by one
    our XML server, and to allow you to customize the events you
    receive.  If you report() a result via this function, the server
    will parse its text and convert it into a SimpleResult, and pass it
    back to XML listeners.

    The fields of a SimpleResult are

      SimpleResultT = 
          attribute id { xsd:int },
          element name { text },
          element type { xsd:int },
          element time { xsd:unsignedLong },
          element tsc { xsd:unsignedLong },
          element counter { xsd:unsignedLong },
          element resultValue { text },
          element msg { text }?,
          element outputValues { NameValue* }
      SimpleResult = element simpleResult { SimpleResultT }

    We provide a global result counter that we update each time result()
    is called; this is the `id' attribute.  The report() tn argument
    becomes name; report.tid becomes type; report.rv becomes
    resultValue; report.msg becomes msg; and any of the probe's values
    are passed back as strings in outputValues.  The report() rt
    argument says what type of result this is (whether it is 'i'
    (intermediate) or 'f' (final)).  This is interpreted specifically by
    the VMI XML analysis server's RESULT autoparsing code.  If it is an
    'i' RESULT, it is sent to any of the XML analysis server's listeners
    immediately, and is then discarded.  If it is an 'f' RESULT, the XML
    analysis server immediately notifies listeners as well, but it saves
    the RESULT for later retrieval by an XML client.  'i' RESULTs are
    not saved for later retrieval.

    We also can report back thread context information (i.e., id, name,
    parent id, uid, gid; or other target backend-specific values --
    i.e. registers, thread metadata, etc).  You can control how much
    detail and for which threads it's reported.  If ttdetail is not set,
    it defaults to 0.  ttdetail==-2 means print only tid; -1 means print
    only tid and name; 0 means print tid, name, ptid, uid, gid, and the
    0-th level of information from the target backend.  Anything greater
    than 0 increases the amount of data the backend will produce.  Then,
    you can also select which threads are printed via the ttctx field.
    If ttctx==all, all known threads will be displayed.  If ttctx==self,
    only the thread that triggered the probe will be displayed.  If
    ttctx==hier, then the thread hierarchy starting with the thread that
    triggered the probe, to its root parent, will be displayed.  If
    ttctx==none, no threads will be displayed.  The default is none.  If
    bt is not set, it defaults to 0 (no backtrace).  Otherwise, a
    backtrace is printed for each thread printed as a result of ttctx's
    value (so to get a backtrace, you must set *both* ttctx and bt!).

  enable(<probeFilterId>)  {n}
  disable(<probeFilterId>) {n}

    Enables or disables the given <probeFilterId>.  Enabling the current
    filter has no effect (unless a previous matching filter for the
    current symbol disabled it!).  If you disable yourself,

  remove(<probeFilterId>)  {n}

    Removes the <probeFilterId>.  If you remove yourself, this is the
    last action that will be run for this filter!  So don't put any
    actions after this one on this filter's line.

  abort(<returncode>)      {1}

    If <symbol> was a function, we will attempt to immediately "return"
    from the function on x86 architectures.  <returncode> is a long
    int.  The abort will not happen until after all the filters on this
    <symbol> have run, so there are no restrictions on its ordering.
    HOWEVER, even if you specify an abort() in multiple filters on the
    same symbol, and more than one filter matches, only the first
    abort() will actually happen.

  exit(<exitcode>)         {1}

    If you detect some condition that means spf should exit, you can
    make that happen via exit, and your <exitcode> will be returned.
    exit() will not take effect until all filters for the current symbol
    have finished running, so there are no restrictions on its ordering.


Have fun!  As usual, applying extra SPF is the way to go ;).
