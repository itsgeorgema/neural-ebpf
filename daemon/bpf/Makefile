CLANG ?= clang
ARCH  ?= x86

# Generate vmlinux.h from running kernel (requires bpftool)
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

cpu_monitor.bpf.o: cpu_monitor.bpf.c vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	  -I/usr/include/x86_64-linux-gnu \
	  -c $< -o $@

fd_monitor.bpf.o: fd_monitor.bpf.c vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	  -I/usr/include/x86_64-linux-gnu \
	  -c $< -o $@

all: cpu_monitor.bpf.o fd_monitor.bpf.o

clean:
	rm -f *.o vmlinux.h

.PHONY: all clean
