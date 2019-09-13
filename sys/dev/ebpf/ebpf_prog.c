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

#include "ebpf_prog.h"
#include "ebpf_internal.h"

#ifdef _KERNEL
#define KERNEL_PROG_TYPE(type) (&type)
#else
#define KERNEL_PROG_TYPE(type) (&bad_prog_type)
#endif

const struct ebpf_prog_type *ebpf_prog_types[] = {
	[EBPF_PROG_TYPE_BAD]  = &bad_prog_type,
	[EBPF_PROG_TYPE_TEST] = &test_prog_type,
	[EBPF_PROG_TYPE_VFS] = KERNEL_PROG_TYPE(vfs_prog_type),
};

const struct ebpf_prog_type *
ebpf_get_prog_type(uint16_t type)
{
	if (type >= EBPF_PROG_TYPE_MAX) {
		return NULL;
	}

	return ebpf_prog_types[type];
}

int
ebpf_prog_init(struct ebpf_prog *prog_obj, struct ebpf_prog_attr *attr)
{
	if (prog_obj == NULL || attr == NULL ||
			attr->type >= EBPF_PROG_TYPE_MAX ||
			attr->prog == NULL || attr->prog_len == 0) {
		return EINVAL;
	}

	struct ebpf_inst *insts = ebpf_malloc(attr->prog_len);
	if (insts == NULL) {
		return ENOMEM;
	}

	memcpy(insts, attr->prog, attr->prog_len);

	prog_obj->type = ebpf_get_prog_type(attr->type);
	prog_obj->prog_len = attr->prog_len;
	prog_obj->prog = insts;
	prog_obj->deinit = ebpf_prog_deinit_default;
	prog_obj->probe = NULL;

	return 0;
}

int
ebpf_prog_alloc_vm(struct ebpf_prog *prog_obj)
{
	struct ebpf_vm *vm;
	int error;

	vm = ebpf_create();
	if (vm == NULL) {
		error = ENOMEM;
		goto fail;
	}

	prog_obj->vm = vm;

	error = ebpf_prog_init_vm(prog_obj, vm);
	if (error != 0) {
		goto fail;
	}

	error = ebpf_load(vm, prog_obj->prog, prog_obj->prog_len);
	if (error < 0) {
		error = EINVAL;
		goto fail;
	}

#if 0
	if (jit) {
		ebpf_jit_fn fn = ebpf_compile(vm);
		if (fn == NULL) {
			error = EINVAL;
			goto fail;
		}
	}
#endif
	return (0);

fail:
	if (vm != NULL) {
		ebpf_destroy(vm);
		prog_obj->vm = NULL;
	}

	return (error);
}

void
ebpf_prog_deinit_default(struct ebpf_prog *prog_obj, void *arg)
{
	printf("Deinit prog: probe=%p\n", prog_obj->probe);
	if (prog_obj->probe != NULL) {
		ebpf_probe_detach(prog_obj->probe);
	}

	if (prog_obj->vm != NULL) {
		if (prog_obj->type->vm_deinit) {
			prog_obj->type->vm_deinit(prog_obj->vm);
		}
		ebpf_destroy(prog_obj->vm);
	}

	ebpf_free(prog_obj->prog);
}

void
ebpf_prog_deinit(struct ebpf_prog *prog_obj, void *arg)
{
	if (prog_obj == NULL) {
		return;
	}

	if (prog_obj->deinit != NULL) {
		prog_obj->deinit(prog_obj, arg);
	}
}

int
ebpf_prog_init_vm(struct ebpf_prog *prog, struct ebpf_vm *vm)
{
	int error = 0;

	if (prog->type->vm_init) {
		error = prog->type->vm_init(vm);
	}

	return (error);
}

int
ebpf_prog_reserve_cpu(struct ebpf_prog *prog, struct ebpf_vm *vm,
    struct ebpf_vm_state *vm_state)
{

	return (prog->type->reserve_cpu(vm, vm_state));
}

void ebpf_prog_release_cpu(struct ebpf_prog *prog, struct ebpf_vm *vm,
    struct ebpf_vm_state *vm_state)
{

	prog->type->release_cpu(vm, vm_state);
}
