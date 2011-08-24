CC := gcc
LD := ld
SWIG := swig
LEX := flex

PYINCLUDE := /usr/include/python2.5
PYLIB := /usr/lib/python2.5

CFLAGS := -fPIC
CFLAGS += -Wall
CFLAGS += -O2
#CFLAGS += -g
CFLAGS += -I./

# xenaccess
CFLAGS += -D ENABLE_XEN
OBJECTS := xenaccess/linux_core.o
OBJECTS += xenaccess/linux_domain_info.o
OBJECTS += xenaccess/linux_memory.o
OBJECTS += xenaccess/linux_symbols.o
OBJECTS += xenaccess/windows_core.o
OBJECTS += xenaccess/windows_memory.o
OBJECTS += xenaccess/windows_process.o
OBJECTS += xenaccess/windows_symbols.o
OBJECTS += xenaccess/xa_cache.o
OBJECTS += xenaccess/xa_core.o
OBJECTS += xenaccess/xa_domain_info.o
OBJECTS += xenaccess/xa_error.o
OBJECTS += xenaccess/xa_file.o
OBJECTS += xenaccess/xa_memory.o
OBJECTS += xenaccess/xa_pretty_print.o
OBJECTS += xenaccess/xa_symbols.o
OBJECTS += xenaccess/xa_util.o

# vmprobes
CFLAGS += -D VMPROBE_i386
#CFLAGS += -D VMPROBE_DEBUG
OBJECTS += vmprobes/vmprobes.o

# vmtap
#CFLAGS += -D VMTAP_DEBUG
CFLAGS += -I$(PYINCLUDE)
LFLAGS := -shared
LFLAGS += -lxenctrl
LFLAGS += -lxenstore
SFLAGS := -python
WRAPPER := vmtap_wrap.c
PARSER := vmtap_parse.yy.c
OBJECTS += vmtap.o
OBJECTS += vmtap_wrap.o
OBJECTS += vmtap_parse.yy.o
MODULE := vmtap.py
MODBIN := vmtap.pyc
TARGET := _vmtap.so

default:
	@echo "compiling vmtap... (be patient)"
	@$(MAKE) $(TARGET)
	@echo "vmtap compiled"

%_wrap.c: %.i
	@$(SWIG) $(SFLAGS) $<

%.yy.c: %.l
	@$(LEX) -o $@ $<

%.o: %.c
	@$(CC) -c $(CFLAGS) -o $@ $<

%.so: $(WRAPPER) $(PARSER) $(OBJECTS)
	@$(LD) $(LFLAGS) $(OBJECTS) -o $@

clean:
	@$(RM) -f $(WRAPPER)
	@$(RM) -f $(PARSER)
	@$(RM) -f $(OBJECTS)
	@$(RM) -f $(MODULE) $(MODBIN)
	@$(RM) -f $(TARGET)
	@echo "vmtap cleaned"

install:
	@cp $(TARGET) $(PYLIB)
	@cp $(MODULE) $(PYLIB)
	@echo "vmtap installed"

uninstall:
	@$(RM) -f $(PYLIB)/$(TARGET)
	@$(RM) -f $(PYLIB)/$(MODULE)
	@echo "vmtap uninstalled"
