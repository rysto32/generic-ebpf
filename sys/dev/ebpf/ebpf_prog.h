/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
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
#include <sys/ebpf.h>
#include <sys/ebpf_inst.h>

struct ebpf_prog {
	const struct ebpf_prog_type *type;
	struct ebpf_inst *prog;
	uint32_t prog_len;
	void (*deinit)(struct ebpf_prog *, void *);
	struct ebpf_vm *vm;
};

struct ebpf_prog_attr {
	uint16_t type;
	struct ebpf_inst *prog;
	uint32_t prog_len;
};

struct ebpf_vm;
struct ebpf_vm_state;

typedef int (*ebpf_vm_init)(struct ebpf_vm *);
typedef void (*ebpf_vm_deinit)(struct ebpf_vm *);
typedef int (*ebpf_vm_reserve_cpu)(struct ebpf_vm *, struct ebpf_vm_state *);
typedef void (*ebpf_vm_release_cpu)(struct ebpf_vm *, struct ebpf_vm_state *);

struct ebpf_prog_type {
	char name[EBPF_NAME_MAX];
	uint16_t type;
	ebpf_vm_init vm_init;
	ebpf_vm_deinit vm_deinit;
	ebpf_vm_reserve_cpu reserve_cpu;
	ebpf_vm_release_cpu release_cpu;
};

const struct ebpf_prog_type *ebpf_get_prog_type(uint16_t type);
int ebpf_prog_init(struct ebpf_prog *prog_obj, struct ebpf_prog_attr *attr);
int ebpf_prog_alloc_vm(struct ebpf_prog *prog_obj);
void ebpf_prog_deinit_default(struct ebpf_prog *prog_obj, void *arg);
void ebpf_prog_deinit(struct ebpf_prog *prog_obj, void *arg);

int ebpf_prog_init_vm(struct ebpf_prog *prog, struct ebpf_vm *vm);
int ebpf_prog_reserve_cpu(struct ebpf_prog *prog, struct ebpf_vm *vm,
    struct ebpf_vm_state *state);
void ebpf_prog_release_cpu(struct ebpf_prog *prog, struct ebpf_vm *vm,
    struct ebpf_vm_state *state);
