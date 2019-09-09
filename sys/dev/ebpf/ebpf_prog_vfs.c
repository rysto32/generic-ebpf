/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2019 Ryan Stone
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
#include "ebpf_map.h"
#include <sys/ebpf_vm.h>

static void
vfs_vm_attach_func(struct ebpf_vm *vm)
{
	/*
	 * Attach basic external functions
	 */
	ebpf_register(vm, 1, "ebpf_map_update_elem", ebpf_map_update_elem);
	ebpf_register(vm, 2, "ebpf_map_lookup_elem", ebpf_map_lookup_elem);
	ebpf_register(vm, 3, "ebpf_map_delete_elem", ebpf_map_delete_elem);
}

static void
vfs_vm_init(struct ebpf_vm *vm)
{

	vfs_vm_attach_func(vm);
}

struct ebpf_prog_type vfs_prog_type = {
	.name = "vfs",
	.type = EBPF_PROG_TYPE_VFS,
	.vm_init = vfs_vm_init,
};
