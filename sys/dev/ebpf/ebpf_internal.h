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
#include <sys/ebpf_vm.h>
#include <sys/ebpf_inst.h>

#define MAX_INSTS 65536
#define MAX_EXT_FUNCS 64
#define STACK_SIZE 128

struct ebpf_prog;
struct ebpf_probe;

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2,
			     uint64_t arg3, uint64_t arg4);

struct ebpf_vm {
	struct ebpf_inst *insts;
	uint16_t num_insts;
	ebpf_jit_fn jitted;
	size_t jitted_size;
	ext_func *ext_funcs;
	const char **ext_func_names;
};

unsigned int ebpf_lookup_registered_function(struct ebpf_vm *vm,
					     const char *name);
bool ebpf_validate(const struct ebpf_vm *vm, const struct ebpf_inst *insts,
		   uint32_t num_insts);

struct ebpf_probe_state;

int ebpf_probe_attach(struct ebpf_probe *probe, struct ebpf_prog *prog, int jit);
void ebpf_probe_detach(struct ebpf_probe_state *state);
int ebpf_fire(struct ebpf_probe *probe, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5);

int ebpf_copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done);
int ebpf_copyout(const void *kaddr, void *uaddr, size_t len);
int ebpf_dup(int fd);
int ebpf_openat(int fd, const char * path, int flags, int mode);
int ebpf_fstat(int fd, struct stat *sb);
int ebpf_fstatat(int fd, const char *path, struct stat *sb, int flag);
int ebpf_faccessat(int fd, const char *path, int mode, int flag);
int ebpf_set_errno(int error);
int ebpf_set_syscall_retval(int ret0, int ret1);
