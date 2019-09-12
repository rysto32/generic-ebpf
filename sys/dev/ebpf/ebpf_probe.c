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

struct ebpf_probe_state
{
	struct ebpf_probe *probe;
	struct ebpf_prog *prog;
	int jit;
};

int
ebpf_probe_attach(struct ebpf_probe *probe, struct ebpf_prog *prog, int jit)
{
	struct ebpf_probe_state *state;

	state = ebpf_calloc(sizeof(*state), 1);
	if (state == NULL)
		return (ENOMEM);

	state->jit = jit;
	state->probe = probe;
	state->prog = prog;

	// XXX we need locking here to deal with close() racing with attach()
	probe->module_state = state;
	prog->probe = state;
	atomic_set_acq_int(&probe->active, 1);

	printf("Attach to probe '%s'\n", probe->name);
	return (0);
}

void
ebpf_probe_detach(struct ebpf_probe_state *state)
{
	struct ebpf_probe *probe;

	probe = state->probe;
	printf("Detach from '%s'\n", probe->name);

	probe->module_state = NULL;

	ebpf_probe_drain(probe);

	ebpf_free(state);
}

int
ebpf_fire(struct ebpf_probe *probe, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{
	ebpf_thread *td;
	struct ebpf_probe_state *state;
	struct ebpf_vm *vm;
	struct ebpf_vm_state vm_state;
	int error, ret;

	state = probe->module_state;
	if (state == NULL)
		return (EBPF_ACTION_CONTINUE);

	ebpf_vm_init_state(&vm_state);

	vm_state.next_vm = state->prog->vm;
	vm_state.next_vm_args[0] = arg0;
	vm_state.next_vm_args[1] = arg1;
	vm_state.num_args = 2;

	td = ebpf_curthread();

	while (vm_state.next_vm != NULL && vm_state.num_tail_calls < 32) {
		vm = vm_state.next_vm;
		vm_state.next_vm = NULL;

		error = ebpf_prog_reserve_cpu(state->prog, vm, &vm_state);
		if (error != 0) {
			ebpf_probe_set_errno(&vm_state, error);
			return (EBPF_ACTION_RETURN);
		}

		if (state->jit) {
			ret = ebpf_exec_jit(vm, &vm_state);
		} else {
			ret = ebpf_exec(vm, &vm_state);
		}

		ebpf_prog_release_cpu(state->prog, vm, &vm_state);
		if (vm_state.vm_fp != NULL) {
			ebpf_fdrop(vm_state.vm_fp, td);
			vm_state.vm_fp = NULL;
		}

		if (vm_state.deferred_func != 0) {
			vm_state.deferred_func(&vm_state);
			vm_state.deferred_func = NULL;
		}
		vm_state.num_tail_calls++;
	}

	return (ret);
}
