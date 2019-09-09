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

void
ebpf_prog_deinit_default(struct ebpf_prog *prog_obj, void *arg)
{
	printf("Deinit prog: probe=%p\n", prog_obj->probe);
	if (prog_obj->probe != NULL) {
		ebpf_probe_detach(prog_obj->probe);
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

void
ebpf_prog_init_vm(struct ebpf_prog *prog, struct ebpf_vm *vm)
{

	if (prog->type->vm_init) {
		prog->type->vm_init(vm);
	}
}
