CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
#INCLUDES := -I/usr/local/include -I/usr/local/include/bpf
INCLUDES := -I/usr/include/bpf
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APPS = lsm

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(APPS)
	$(Q)rm -rf $(wildcard *.o)
	$(Q)rm -rf $(wildcard *.skel.h)

%.bpf.o: %.bpf.c
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

%.skel.h: %.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)sudo $(BPFTOOL) gen skeleton $< > $@

%.o: %.c %.skel.h
	$(call msg,CC,$@)
	$(Q)$(CLANG) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APPS): %: %.o
	$(call msg,BINARY,$@)
	$(Q)$(CLANG) $(CFLAGS) $(INCLUDES) $^ -lbpf -lelf -lz -o $@
