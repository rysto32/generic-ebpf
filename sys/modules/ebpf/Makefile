.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf ${.CURDIR}/../../dev/ebpf_dev

IDENT  != uname -i

CFLAGS += -I$(KSRC)/sys/$(MACHINE)/compile/$(IDENT)
CFLAGS += -I../../
CFLAGS += -Wall
CFLAGS += -std=c99
CFLAGS += -DEBPF_HOOKS

KMOD    = ebpf

CORES += ebpf_allocator.c
CORES += ebpf_freebsd.c
CORES += ebpf_map.c
CORES += ebpf_probe.c
CORES += ebpf_prog.c
CORES += ebpf_verifer.c
CORES += ebpf_vm.c

MAPS += ebpf_map_array.c
MAPS += ebpf_map_bad.c
MAPS += ebpf_map_hashtable.c

PROGS += ebpf_prog_bad.c
PROGS += ebpf_prog_test.c
PROGS += ebpf_prog_vfs.c

.if $(MACHINE) == "amd64"
CORES += ../../amd64/amd64/ebpf_jit_x86_64.c
.endif

SRCS += ebpf_dev_freebsd.c
SRCS += ebpf_obj.c
SRCS += ebpf_dev.c

SRCS += $(CORES)
SRCS += $(MAPS)
SRCS += $(PROGS)

DEBUG_FLAGS=-g

realinstall:
	install ebpf.ko $(DESTDIR)

.include <bsd.kmod.mk>
