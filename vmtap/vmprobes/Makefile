CC:= gcc

CFLAGS:= -fPIC
CFLAGS+= -Wall
CFLAGS+= -O2
#CFLAGS+= -g
CFLAGS+= -I./

LFLAGS+= -lxenctrl
LFLAGS+= -lxenstore

# xenaccess
CFLAGS+= -D ENABLE_XEN
OBJECTS:= ../xenaccess/linux_core.o
OBJECTS+= ../xenaccess/linux_domain_info.o
OBJECTS+= ../xenaccess/linux_memory.o
OBJECTS+= ../xenaccess/linux_symbols.o
OBJECTS+= ../xenaccess/windows_core.o
OBJECTS+= ../xenaccess/windows_memory.o
OBJECTS+= ../xenaccess/windows_process.o
OBJECTS+= ../xenaccess/windows_symbols.o
OBJECTS+= ../xenaccess/xa_cache.o
OBJECTS+= ../xenaccess/xa_core.o
OBJECTS+= ../xenaccess/xa_domain_info.o
OBJECTS+= ../xenaccess/xa_error.o
OBJECTS+= ../xenaccess/xa_file.o
OBJECTS+= ../xenaccess/xa_memory.o
OBJECTS+= ../xenaccess/xa_pretty_print.o
OBJECTS+= ../xenaccess/xa_symbols.o
OBJECTS+= ../xenaccess/xa_util.o

# vmprobes
CFLAGS+= -D VMPROBE_i386
CFLAGS+= -D VMPROBE_SIGNAL
#CFLAGS+= -D VMPROBE_DEBUG
OBJECTS+= vmprobes.o

# vmprobes examples
EXAMPLES:= examples/vmprobebio
EXAMPLES+= examples/vmprobeopen

default: $(OBJECTS) $(EXAMPLES)
	@echo "vmprobes compiled"

%.o: %.c
	@$(CC) -c $(CFLAGS) -o $@ $<

examples/%: examples/%.c
	@$(CC) $(CFLAGS) $(LFLAGS) $(OBJECTS) -o $@ $<

clean:
	@#rm -f $(OBJECTS) $(EXAMPLES)
	@rm -f vmprobes.o $(EXAMPLES)
	@echo "vmprobes cleaned"
