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

#include "ebpf_internal.h"
#include "ebpf_prog.h"

#include <sys/ebpf_probe.h>
#include <sys/refcount.h>

struct ebpf_probe_state
{
	struct ebpf_probe *probe;
	struct ebpf_obj_prog *prog;
	int jit;
	uint32_t refcount;
};

int
ebpf_probe_attach(const char * pr_name, struct ebpf_obj_prog *prog, int jit)
{
	struct ebpf_probe *probe;
	struct ebpf_probe_state *state;

	state = ebpf_calloc(sizeof(*state), 1);
	if (state == NULL)
		return (ENOMEM);

	ebpf_refcount_init(&state->refcount, 1);
	state->jit = jit;
	state->prog = prog;

	probe = ebpf_activate_probe(pr_name, state);
	if (probe == NULL) {
		ebpf_free(state);
		return (ENOENT);
	}

	state->probe = probe;

	return (0);
}

void *
ebpf_probe_clone(struct ebpf_probe *probe, void *a)
{
	struct ebpf_probe_state *state;

	state = a;
	ebpf_refcount_acquire(&state->refcount);

	return (state);
}

void
ebpf_probe_release(struct ebpf_probe *probe, void *a)
{
	struct ebpf_probe_state *state;

	state = a;

	if (refcount_release(&state->refcount)) {
		ebpf_fdrop(state->prog->obj.f, ebpf_curthread());
		ebpf_free(state);
	}
}

int
ebpf_fire(struct ebpf_probe *probe, void *a, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{
	ebpf_thread *td;
	struct ebpf_probe_state *state;
	struct ebpf_vm *vm;
	ebpf_file *vm_fp;
	struct ebpf_vm_state vm_state;
	int error, ret;

	state = a;

	ebpf_vm_init_state(&vm_state);

	vm_state.next_vm = state->prog->prog.vm;
	vm_state.next_vm_args[0] = arg0;
	vm_state.next_vm_args[1] = arg1;
	vm_state.num_args = 2;

	vm_fp = NULL;

	td = ebpf_curthread();

	while (vm_state.next_vm != NULL && vm_state.num_tail_calls < 32) {
		vm = vm_state.next_vm;
		vm_state.next_vm = NULL;

		error = ebpf_prog_reserve_cpu(&state->prog->prog, vm, &vm_state);
		if (error != 0) {
			ebpf_probe_set_errno(&vm_state, error);
			return (EBPF_ACTION_RETURN);
		}

		if (state->jit) {
			ret = ebpf_exec_jit(vm, &vm_state);
		} else {
			ret = ebpf_exec(vm, &vm_state);
		}

		ebpf_prog_release_cpu(&state->prog->prog, vm, &vm_state);

		/* Drop reference on program we just ran. */
		if (vm_fp != NULL) {
			ebpf_fdrop(vm_fp, td);
		}

		/* Grab pointer to program we will run on next iteration */
		vm_fp = vm_state.vm_fp;
		vm_state.vm_fp = NULL;

		if (vm_state.deferred_func != 0) {
			vm_state.deferred_func(&vm_state);
			vm_state.deferred_func = NULL;
		}
		vm_state.num_tail_calls++;
	}

	KASSERT(vm_fp == NULL, ("Lost a reference to a program's file*"));

	return (ret);
}
