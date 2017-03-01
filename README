Stackdb: A C Library for "Stackable" Debugging and Virtual Machine Introspection
================================================================================

Stackdb is a C library that allows a user to write programs to debug,
inspect, modify, and analyze the behavior of other running programs ---
from virtual machines (Xen, KVM/QEMU) to Linux userspace programs (via
`ptrace(2)`).  This means Stackdb can be used to debug programs running
on your desktop machine; or it can be used to debug virtual machines and
the programs running inside them!

Stackdb is useful both as a featureful debugger, and as a tool for
Virtual Machine Introspection (i.e., memory forensics, execution
monitoring).  It supports breakpoints, watchpoints, stack unwinding,
multi-threaded program debugging, debugging symbol information (via ELF
and DWARF), and C and C++ programs.  It supports multi-target analysis
--- meaning your Stackdb program can attach to or spawn multiple target
programs (of different types, if desired), and cooperatively analyze or
monitor their behavior.

However, Stackdb's defining feature is its ability to create *stacks* of
debugging targets.  This means that Stackdb drivers (which allow you,
the user, to attach to a running program and debug it) can be
**stacked**, allowing you to attach to and debug a program running in
another program!  For instance, using Stackdb, you can attach to a Xen
virtual machine and the Linux kernel running inside it (the *base*
target); and subsequently attach to a userspace process running inside
that VM (an *overlay* target).  Stackdb's user API functions can be
applied to all targets.  Thus, you can insert a breakpoint on the
`sys_open` system call function in the Linux kernel in your base target,
and another on the `make_child` function in a `bash` process running in
userspace (your *overlay* target).


Supported Platforms
-------------------

Stackdb builds and runs on Linux.  Its base drivers allow you to attach
to the following targets: Xen VMs, KVM/QEMU VMs, Linux userspace
processes.  It provides one *personality* (Stackdb's abstraction for
enhancing its model of the running target), a generic Linux personality
supporting kernels from 2.6.18 to 3.8.x (and possibly higher).  You'll
want to attach the "Linux" personality to any Xen or KVM VM that is
running a Linux kernel).  Its overlay drivers allow you to attach to OS
Processes (i.e., you can attach to any userspace process running in a
base target whose driver and/or personality supports Stackdb's Process
abstraction --- this is one kind of *stack* of targets you can create.
Another overlay driver, the PHP driver, allows you to stack a PHP target
atop a process target and place probes on PHP function symbols.  This
means the following stacks are possible:

  * Xen VM + Linux Personality -> OS Process -> PHP
  * KVM/QEMU VM + Linux Personality -> OS Process -> PHP
  * ptrace -> PHP

and of course, you can use partial stacks of targets, or no stack at
all, if you simply want to inspect a Xen VM.

Finally, Stackdb supports `x86` and `x86_64` architectures.  Your
Stackdb program and target program must be the same architecture; at
present we do not support `x86_64` analysis of an `x86` VM, for
instance.  Stackdb is a research project, first and foremost; sadly, we
have not been able to find time to support all the desirable features of
full architecture abstraction.


Obtaining the Software
----------------------

You can obtain Stackdb at <http://www.flux.utah.edu/software/stackdb>.
You can browse a copy of the source repository at
<https://gitlab.flux.utah.edu/admin/projects/a3/vmi>.


Additional Documentation
------------------------

You can access the online documentation at
<http://a3.pages.flux.utah.edu/vmi>.

You can also read our detailed paper describing Stackdb's design and
internal APIs at <http://www.flux.utah.edu/paper/johnson-vee14>.  This
paper is a great introduction to the Stackdb concept and terminology.
It is still highly relevant and worth reading to understand how the
software works  --- although the APIs described have since expanded.
However, it functions as our "conceptual level" description of Stackdb.

You can build a local copy of the Stackdb documentation by entering the
`doc/` subdirectory and typing `make`.  The build requires (at least)
`doxygen`, `pandoc`, and `pdflatex`.


Authors
-------

Stackdb was written at the [University of Utah], in the [Flux Research
Group], by [David Johnson] (<johnsond@cs.utah.edu>).  It originally grew
out of an `x86`, Xen-based VMI library developed by [Chung Hwan Kim]
(<chungkim@cs.purdue.edu>) (still in the source repository in the
`vmprobes/` subdirectory), but has been entirely rewritten and
significantly expanded into a multi-platform, multi-target, stackable
debugger library.  [Mike Hibler] (<hibler@cs.utah.edu>), [Anton Burtsev]
(<aburtsev@cs.utah.edu>), and [Eric Eide] (<eeide@cs.utah.edu>) have
also contributed to aspects of Stackdb.



[University of Utah]: http://www.utah.edu
[Flux Research Group]: http://www.flux.utah.edu
[David Johnson]: http://www.flux.utah.edu/profile/johnsond
[Chung Hwan Kim]: https://www.cs.purdue.edu/homes/chungkim
[Mike Hibler]: http://www.flux.utah.edu/profile/mike
[Anton Burtsev]: http://www.flux.utah.edu/profile/aburtsev
[Eric Eide]: http://www.flux.utah.edu/profile/eeide
