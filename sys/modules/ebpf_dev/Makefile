.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf_dev

TARGET != uname -m
IDENT  != uname -i

CFLAGS += -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)
CFLAGS += -I../../
CFLAGS += -Wall
CFLAGS += -std=c99
CFLAGS += -DEBPF_HOOKS

KMOD    = ebpf-dev

SRCS += ebpf_dev_freebsd.c
SRCS += ebpf_obj.c
SRCS += ebpf_dev.c

DEBUG_FLAGS=-g

realinstall:
	cp ebpf-dev.ko $(DESTDIR)

.include <bsd.kmod.mk>
