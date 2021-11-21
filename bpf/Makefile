KERNEL ?= /lib/modules/$(shell uname -r)/build/
ARCH=$(shell uname -m)

LINUXINCLUDE += -I$(KERNEL)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNEL)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNEL)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(KERNEL)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(KERNEL)/include
LINUXINCLUDE += -I$(KERNEL)/include/uapi
LINUXINCLUDE += -I$(KERNEL)/include/generated/uapi
LINUXINCLUDE += -I/usr/include/$(ARCH)-linux-gnu/

all: clean bt_bpf.o bt_rt_bpf.o bt_ont_bpf.o

.PHONY: clean
clean:
	rm bt_bpf.o bt_rt_bpf.o bt_ont_bpf.o -f

bt_bpf.o:
	clang -O2 -Wall -target bpf -c bt_bpf.c -o bt_bpf.o $(LINUXINCLUDE)

bt_rt_bpf.o:
	clang -O2 -Wall -target bpf -c bt_rt_bpf.c -o bt_rt_bpf.o $(LINUXINCLUDE)

bt_ont_bpf.o:
	clang -O2 -Wall -target bpf -c bt_ont_bpf.c -o bt_ont_bpf.o $(LINUXINCLUDE)
