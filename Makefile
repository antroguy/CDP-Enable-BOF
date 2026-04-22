CC=x86_64-w64-mingw32-gcc
OBJCOPY=x86_64-w64-mingw32-objcopy
CFLAGS=-O2 -c -Wall -Wextra -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions -fno-stack-protector
INCLUDES=-I .
OUT=cdp_enable_bof.o

.PHONY: all clean

all: $(OUT)

$(OUT): cdp_enable_bof.c
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES)
	$(OBJCOPY) --remove-section .pdata --remove-section .xdata --remove-section .eh_frame $@

clean:
	rm -f $(OUT)
