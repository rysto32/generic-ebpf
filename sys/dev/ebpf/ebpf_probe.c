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
	struct ebpf_vm *vm;
	int jit;
};

int
ebpf_probe_attach(struct ebpf_probe *probe, struct ebpf_prog *prog, int jit)
{
	struct ebpf_vm *vm;
	struct ebpf_probe_state *state;
	int error;

	state = ebpf_calloc(sizeof(*state), 1);
	if (state == NULL)
		return (ENOMEM);

	vm = ebpf_create();
	if (vm == NULL) {
		error = ENOMEM;
		goto fail;
	}

	state->vm = vm;
	ebpf_prog_init_vm(prog, vm);

	error = ebpf_load(vm, prog->prog, prog->prog_len);
	if (error < 0) {
		error = EINVAL;
		goto fail;
	}

	if (jit) {
		ebpf_jit_fn fn = ebpf_compile(vm);
		if (fn == NULL) {
			error = EINVAL;
			goto fail;
		}
	}

	state->jit = jit;
	state->probe = probe;

	// XXX we need locking here to deal with close() racing with attach()
	probe->module_state = state;
	prog->probe = state;
	atomic_set_acq_int(&probe->active, 1);

	printf("Attach to probe '%s'\n", probe->name);
	return (0);

fail:
	if (state && state->vm) {
		ebpf_destroy(vm);
	}
	ebpf_free(state);
	return (error);
}

void
ebpf_probe_detach(struct ebpf_probe_state *state)
{
	struct ebpf_probe *probe;

	probe = state->probe;
	printf("Detach from '%s'\n", probe->name);

	probe->module_state = NULL;
	atomic_set_rel_int(&probe->active, 0);

	ebpf_probe_drain(probe);

	ebpf_destroy(state->vm);
	ebpf_free(state);
}

int
ebpf_fire(struct ebpf_probe *probe, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{
	struct ebpf_probe_state *state;

	state = probe->module_state;
	if (state == NULL)
		return (EBPF_ACTION_CONTINUE);

	if (state->jit) {
		return ebpf_exec_jit(state->vm, (void*)arg0, arg1);
	} else {
		return ebpf_exec(state->vm, (void*)arg0, arg1);
	}
}
