CC:= gcc
LD:= ld
SWIG:= swig

PYINCLUDE:= /usr/include/python2.5
PYLIB:= /usr/lib/python2.5

CFLAGS:= -fPIC
#CFLAGS+= -Wall
CFLAGS+= -O2
#CFLAGS+= -g
CFLAGS+= -I./

LFLAGS+= -lxenctrl
LFLAGS+= -lxenstore

# xenaccess
CFLAGS+= -D ENABLE_XEN
OBJECTS:= xenaccess/linux_core.o
OBJECTS+= xenaccess/linux_domain_info.o
OBJECTS+= xenaccess/linux_memory.o
OBJECTS+= xenaccess/linux_symbols.o
OBJECTS+= xenaccess/windows_core.o
OBJECTS+= xenaccess/windows_memory.o
OBJECTS+= xenaccess/windows_process.o
OBJECTS+= xenaccess/windows_symbols.o
OBJECTS+= xenaccess/xa_cache.o
OBJECTS+= xenaccess/xa_core.o
OBJECTS+= xenaccess/xa_domain_info.o
OBJECTS+= xenaccess/xa_error.o
OBJECTS+= xenaccess/xa_file.o
OBJECTS+= xenaccess/xa_memory.o
OBJECTS+= xenaccess/xa_pretty_print.o
OBJECTS+= xenaccess/xa_symbols.o
OBJECTS+= xenaccess/xa_util.o

# vmprobes
CFLAGS+= -D VMPROBE_i386
#CFLAGS+= -D VMPROBE_DEBUG
OBJECTS+= vmprobes/vmprobes.o

# vmtap
#CFLAGS+= -D VMTAP_DEBUG
CFLAGS+= -I$(PYINCLUDE)
LFLAGS+= -shared
SFLAGS:= -python
WRAPPER:= vmtap_wrap.c
OBJECTS+= vmtap.o
OBJECTS+= vmtap_wrap.o
MODULE:= vmtap.py
SHARED:= _vmtap.so

default: $(WRAPPER) $(OBJECTS) $(SHARED)
	@echo "vmtap compiled"

%_wrap.c: %.i
	@$(SWIG) $(SFLAGS) $<

%.o: %.c
	@$(CC) -c $(CFLAGS) -o $@ $<

%.so:
	@$(LD) $(LFLAGS) $(OBJECTS) -o $@

clean:
	@rm -f $(WRAPPER) $(OBJECTS) $(MODULE)* $(SHARED)
	@echo "vmtap cleaned"

install:
	@cp $(SHARED) $(PYLIB)
	@cp $(MODULE) $(PYLIB)
	@echo "vmtap installed"

uninstall:
	@rm -f $(PYLIB)/$(SHARED)
	@rm -f $(PYLIB)/$(MODULE)
	@echo "vmtap uninstalled"
