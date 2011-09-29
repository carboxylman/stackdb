CC := gcc

CFLAGS := -fPIC
CFLAGS += -Wall
CFLAGS += -O2
CFLAGS += -g
CFLAGS += -I./

# xenaccess
CFLAGS += -D ENABLE_XEN -D XA_DEBUG
OBJECTS := linux_core.o
OBJECTS += linux_domain_info.o
OBJECTS += linux_memory.o
OBJECTS += linux_symbols.o
OBJECTS += windows_core.o
OBJECTS += windows_memory.o
OBJECTS += windows_process.o
OBJECTS += windows_symbols.o
OBJECTS += xa_cache.o
OBJECTS += xa_core.o
OBJECTS += xa_domain_info.o
OBJECTS += xa_error.o
OBJECTS += xa_file.o
OBJECTS += xa_memory.o
OBJECTS += xa_pretty_print.o
OBJECTS += xa_symbols.o
OBJECTS += xa_util.o

default: Makefile $(OBJECTS)
	@echo "xenaccess compiled"

%.o: %.c
	@$(CC) -c $(CFLAGS) -o $@ $<

clean:
	@rm -f $(OBJECTS)
	@echo "xenaccess cleaned"
