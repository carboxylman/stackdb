CC := gcc

CFLAGS := -fPIC
CFLAGS += -Wall
CFLAGS += -O2
#CFLAGS += -g
CFLAGS += -I../
CFLAGS += -I./

# xenaccess
CFLAGS += -D ENABLE_XEN
#CFLAGS += -D XA_DEBUG
OBJECTS := ../xenaccess/linux_core.o
OBJECTS += ../xenaccess/linux_domain_info.o
OBJECTS += ../xenaccess/linux_memory.o
OBJECTS += ../xenaccess/linux_symbols.o
OBJECTS += ../xenaccess/windows_core.o
OBJECTS += ../xenaccess/windows_memory.o
OBJECTS += ../xenaccess/windows_process.o
OBJECTS += ../xenaccess/windows_symbols.o
OBJECTS += ../xenaccess/xa_cache.o
OBJECTS += ../xenaccess/xa_core.o
OBJECTS += ../xenaccess/xa_domain_info.o
OBJECTS += ../xenaccess/xa_error.o
OBJECTS += ../xenaccess/xa_file.o
OBJECTS += ../xenaccess/xa_memory.o
OBJECTS += ../xenaccess/xa_pretty_print.o
OBJECTS += ../xenaccess/xa_symbols.o
OBJECTS += ../xenaccess/xa_util.o

# vmprobes
CFLAGS += -D VMPROBE_i386
CFLAGS += -D VMPROBE_SIGNAL
CFLAGS += -D VMPROBE_BENCHMARK
#CFLAGS += -D VMPROBE_DEBUG
OBJECTS += vmprobes.o

# vmprobes examples
LFLAGS := -lxenctrl
LFLAGS += -lxenstore
EXAMPLES := examples/vmprobebio
EXAMPLES += examples/vmprobeopen
EXAMPLES += examples/vmprobenull

default:
	@echo "compiling vmprobes (be patient)"
	@$(MAKE) $(EXAMPLES)
	@echo "vmprobes compiled"

%.o: %.c
	@$(CC) -c $(CFLAGS) -o $@ $<

examples/%: examples/%.c $(OBJECTS)
	@$(CC) $(CFLAGS) $(LFLAGS) $(OBJECTS) -o $@ $<

clean:
	@$(RM) -f $(OBJECTS)
	@$(RM) -f $(EXAMPLES)
	@echo "vmprobes cleaned"
