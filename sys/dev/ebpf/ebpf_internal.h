/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017-2018 Yutaro Hayakawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "ebpf_platform.h"
#include "ebpf_prog.h"
#include <sys/ebpf_vm.h>
#include <sys/ebpf_inst.h>

#include <dev/ebpf_dev/ebpf_dev_platform.h>

#define MAX_INSTS 4096
#define MAX_EXT_FUNCS 64
#define STACK_SIZE 128

struct ebpf_prog;
struct ebpf_probe;

struct ebpf_inst;

struct ebpf_vm_state;

typedef uint64_t (*ext_func)(struct ebpf_vm_state *, uint64_t arg0, uint64_t arg1, uint64_t arg2,
			     uint64_t arg3, uint64_t arg4);

struct ebpf_vm {
	struct ebpf_inst *insts;
	uint16_t num_insts;
	ebpf_jit_fn jitted;
	size_t jitted_size;
	ext_func *ext_funcs;
	const char **ext_func_names;

	ebpf_vm_deinit progtype_deinit;
	void *progtype_state;
};

struct ebpf_vm_state
{
	struct ebpf_vm *next_vm;
	ebpf_file *vm_fp;
	uint64_t next_vm_args[5];
	int num_args;
	void (*deferred_func)(struct ebpf_vm_state *);
	int cpu;
	int num_tail_calls;

	union {
		struct {
			void *arg;
			int fd;
			int options;
			struct rusage rusage;
		} wait4;
	} scratch;
};

unsigned int ebpf_lookup_registered_function(struct ebpf_vm *vm,
					     const char *name);
bool ebpf_validate(const struct ebpf_vm *vm, const struct ebpf_inst *insts,
		   uint32_t num_insts);

int ebpf_fd_to_program(ebpf_thread *td, int fd, ebpf_file **fp, struct ebpf_prog **prog);

void ebpf_vm_init_state(struct ebpf_vm_state *state);

int ebpf_probe_attach(const char *, struct ebpf_obj_prog *prog, int jit);
int ebpf_fire(struct ebpf_probe *probe, void *, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5);
void *ebpf_probe_clone(struct ebpf_probe *, void *);
void ebpf_probe_release(struct ebpf_probe *, void *);

int ebpf_probe_copyinstr(struct ebpf_vm_state *, const void *uaddr, void *kaddr,
size_t len, size_t *done);
int ebpf_probe_copyout(struct ebpf_vm_state *, const void *kaddr, void *uaddr,
    size_t len);
int ebpf_probe_dup(struct ebpf_vm_state *, int fd);
int ebpf_probe_openat(struct ebpf_vm_state *, int fd, const char * path,
    int flags, int mode);
int ebpf_probe_fstat(struct ebpf_vm_state *, int fd, struct stat *sb);
int ebpf_probe_fstatat(struct ebpf_vm_state *, int fd, const char *path,
    struct stat *sb, int flag);
int ebpf_probe_faccessat(struct ebpf_vm_state *, int fd, const char *path,
    int mode, int flag);
int ebpf_probe_set_errno(struct ebpf_vm_state *, int error);
int ebpf_probe_set_syscall_retval(struct ebpf_vm_state *, int ret0, int ret1);
pid_t ebpf_probe_pdfork(struct ebpf_vm_state *, int *fd, int flags);
int ebpf_probe_pdwait4_nohang(struct ebpf_vm_state *, int fd, int* status,
    int options, struct rusage *ru);
int ebpf_probe_pdwait4_defer(struct ebpf_vm_state *, int fd, int options,
    void *arg, void *next);
int ebpf_probe_fexecve(struct ebpf_vm_state *, int fd, char ** argv,
    char ** envp, char ** argv_prepend);
void *ebpf_probe_memset(struct ebpf_vm_state *, void *, int, size_t);
int ebpf_probe_readlinkat(struct ebpf_vm_state *, int fd, const char *path,
    char *buf, size_t bufsize);
int ebpf_probe_exec_get_interp(struct ebpf_vm_state *, int fd, char *buf,
    size_t bufsize, int *type);
int ebpf_probe_strncmp(struct ebpf_vm_state *, const char *a, const char *b,
    size_t len);
int ebpf_probe_canonical_path(struct ebpf_vm_state *, char *base,
    const char * rela, size_t bufsize);
int ebpf_probe_renameat(struct ebpf_vm_state *, int fromfd, const char *from,
    int tofd, const char *to);
int ebpf_probe_mkdirat(struct ebpf_vm_state *, int fd, const char *path,
    mode_t mode);
int ebpf_probe_fchdir(struct ebpf_vm_state *, int fd);
pid_t ebpf_probe_getpid(struct ebpf_vm_state *);
int ebpf_probe_get_errno(struct ebpf_vm_state *);
int ebpf_probe_copyin(struct ebpf_vm_state *s, const void *, void *, size_t);
int ebpf_probe_ktrnamei(struct ebpf_vm_state *s, char *);
int ebpf_probe_symlink_path(struct ebpf_vm_state *, char *base,
    const char * rela, size_t bufsize);
size_t ebpf_probe_strlcpy(struct ebpf_vm_state *, char *dest,
    const char * src, size_t bufsize);
