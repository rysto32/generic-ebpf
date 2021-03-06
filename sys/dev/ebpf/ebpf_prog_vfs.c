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
#include "ebpf_internal.h"
#include <sys/ebpf_vm.h>
#include <sys/ebpf_function_idx.h>

#include <sys/sx.h>

struct vfs_vm_state
{
	struct sx * cpu_sx;
};

static void vfs_vm_deinit(struct ebpf_vm *vm);

static void
vfs_vm_attach_func(struct ebpf_vm *vm)
{
	/*
	 * Attach basic external functions
	 */
	ebpf_register(vm, EBPF_FUNC_ebpf_map_update_elem, "ebpf_map_update_elem", ebpf_map_update_elem);
	ebpf_register(vm, EBPF_FUNC_ebpf_map_lookup_elem, "ebpf_map_lookup_elem", ebpf_map_lookup_elem);
	ebpf_register(vm, EBPF_FUNC_ebpf_map_delete_elem, "ebpf_map_delete_elem", ebpf_map_delete_elem);
	ebpf_register(vm, EBPF_FUNC_ebpf_map_lookup_path, "ebpf_map_path_lookup", ebpf_map_path_lookup);
	ebpf_register(vm, EBPF_FUNC_ebpf_map_enqueue, "ebpf_map_enqueue", ebpf_map_enqueue);
	ebpf_register(vm, EBPF_FUNC_ebpf_map_dequeue, "ebpf_map_dequeue", ebpf_map_dequeue);

	ebpf_register(vm, EBPF_FUNC_copyinstr, "copyinstr", ebpf_probe_copyinstr);
	ebpf_register(vm, EBPF_FUNC_copyout, "copyout", ebpf_probe_copyout);
	ebpf_register(vm, EBPF_FUNC_dup, "dup", ebpf_probe_dup);
	ebpf_register(vm, EBPF_FUNC_openat, "openat", ebpf_probe_openat);
	ebpf_register(vm, EBPF_FUNC_fstat, "fstat", ebpf_probe_fstat);
	ebpf_register(vm, EBPF_FUNC_fstatat, "fstatat", ebpf_probe_fstatat);
	ebpf_register(vm, EBPF_FUNC_faccessat, "faccessat", ebpf_probe_faccessat);
	ebpf_register(vm, EBPF_FUNC_set_errno, "set_errno", ebpf_probe_set_errno);
	ebpf_register(vm, EBPF_FUNC_set_syscall_retval, "set_syscall_retval",
	    ebpf_probe_set_syscall_retval);
	ebpf_register(vm, EBPF_FUNC_pdfork, "pdfork", ebpf_probe_pdfork);
	ebpf_register(vm, EBPF_FUNC_pdwait4_nohang, "pdwait4_nohang", ebpf_probe_pdwait4_nohang);
	ebpf_register(vm, EBPF_FUNC_pdwait4_defer, "pdwait4_defer", ebpf_probe_pdwait4_defer);
	ebpf_register(vm, EBPF_FUNC_fexecve, "fexecve", ebpf_probe_fexecve);
	ebpf_register(vm, EBPF_FUNC_memset, "memset", ebpf_probe_memset);
	ebpf_register(vm, EBPF_FUNC_readlinkat, "readlinkat", ebpf_probe_readlinkat);
	ebpf_register(vm, EBPF_FUNC_exec_get_interp, "exec_get_interp", ebpf_probe_exec_get_interp);
	ebpf_register(vm, EBPF_FUNC_strncmp, "strncmp", ebpf_probe_strncmp);
	ebpf_register(vm, EBPF_FUNC_canonical_path, "canonical_path", ebpf_probe_canonical_path);
	ebpf_register(vm, EBPF_FUNC_renameat, "renameat", ebpf_probe_renameat);
	ebpf_register(vm, EBPF_FUNC_mkdirat, "mkdirat", ebpf_probe_mkdirat);
	ebpf_register(vm, EBPF_FUNC_fchdir, "fchdir", ebpf_probe_fchdir);
	ebpf_register(vm, EBPF_FUNC_getpid, "getpid", ebpf_probe_getpid);
	ebpf_register(vm, EBPF_FUNC_get_errno, "get_errno", ebpf_probe_get_errno);
	ebpf_register(vm, EBPF_FUNC_copyin, "copyin", ebpf_probe_copyin);
	ebpf_register(vm, EBPF_FUNC_ktrnamei, "ktrnamei", ebpf_probe_ktrnamei);
	ebpf_register(vm, EBPF_FUNC_symlink_path, "symlink_path", ebpf_probe_symlink_path);
	ebpf_register(vm, EBPF_FUNC_strlcpy, "strlcpy", ebpf_probe_strlcpy);
	ebpf_register(vm, EBPF_FUNC_kqueue, "kqueue", ebpf_probe_kqueue);
	ebpf_register(vm, EBPF_FUNC_kevent_install, "kevent_install", ebpf_probe_kevent_install);
	ebpf_register(vm, EBPF_FUNC_kevent_poll, "kevent_poll", ebpf_probe_kevent_poll);
	ebpf_register(vm, EBPF_FUNC_kevent_block, "kevent_block", ebpf_probe_kevent_block);
	ebpf_register(vm, EBPF_FUNC_close, "close", ebpf_probe_close);
	ebpf_register(vm, EBPF_FUNC_get_syscall_retval, "get_syscall_retval", ebpf_probe_get_syscall_retval);
	ebpf_register(vm, EBPF_FUNC_symlinkat, "symlinkat", ebpf_probe_symlinkat);
	ebpf_register(vm, EBPF_FUNC_resolve_one_symlink, "resolve_one_symlink", ebpf_probe_resolve_one_symlink);
	ebpf_register(vm, EBPF_FUNC_utimensat, "utimensat", ebpf_probe_utimensat);
	ebpf_register(vm, EBPF_FUNC_fcntl, "fcntl", ebpf_probe_fcntl);
	ebpf_register(vm, EBPF_FUNC_unlinkat, "unlinkat", ebpf_probe_unlinkat);
	ebpf_register(vm, EBPF_FUNC_fchown, "fchown", ebpf_probe_fchown);
	ebpf_register(vm, EBPF_FUNC_fchownat, "fchownat", ebpf_probe_fchownat);
	ebpf_register(vm, EBPF_FUNC_fchmod, "fchmod", ebpf_probe_fchmod);
	ebpf_register(vm, EBPF_FUNC_fchmodat, "fchmodat", ebpf_probe_fchmodat);
	ebpf_register(vm, EBPF_FUNC_futimens, "futimens", ebpf_probe_futimens);
	ebpf_register(vm, EBPF_FUNC_linkat, "linkat", ebpf_probe_linkat);
}

static int
vfs_vm_init(struct ebpf_vm *vm)
{
	struct vfs_vm_state *state;
	int i, ncpu, error;

	vfs_vm_attach_func(vm);

	state = ebpf_calloc(sizeof(struct vfs_vm_state), 1);
	if (state == NULL) {
		return (ENOMEM);
	}

	ncpu = ebpf_ncpus();

	state->cpu_sx = ebpf_calloc(sizeof(struct sx), ncpu);
	if (state->cpu_sx == NULL) {
		error = ENOMEM;
		goto fail;
	}

	for (i = 0; i < ncpu; ++i) {
		sx_init(&state->cpu_sx[i], "ebpf_vfs_cpu_sx");
	}

	vm->progtype_deinit = vfs_vm_deinit;
	vm->progtype_state = state;
	return (0);

fail:
	ebpf_free(state);

	return (error);
}

static void
vfs_vm_deinit(struct ebpf_vm *vm)
{
	struct vfs_vm_state *state;
	int i, ncpu;

	state = vm->progtype_state;

	if (state && state->cpu_sx) {
		ncpu = ebpf_ncpus();

		for (i = 0; i < ncpu; ++i) {
			sx_destroy(&state->cpu_sx[i]);
		}

		ebpf_free(state->cpu_sx);
	}

	ebpf_free(state);
	vm->progtype_state = NULL;
}

static int
vfs_reserve_cpu(struct ebpf_vm *vm, struct ebpf_vm_state *vm_state)
{
	struct vfs_vm_state *state;
	int c, error;

	state = vm->progtype_state;
	c = ebpf_curcpu();
	error = sx_slock_sig(&state->cpu_sx[c]);
	if (error != 0) {
		return (error);
	}

	vm_state->cpu = c;
	return (0);
}

static void
vfs_release_cpu(struct ebpf_vm *vm, struct ebpf_vm_state *vm_state)
{
	struct vfs_vm_state *state;

	state = vm->progtype_state;
	sx_sunlock(&state->cpu_sx[vm_state->cpu]);
}

struct ebpf_prog_type vfs_prog_type = {
	.name = "vfs",
	.type = EBPF_PROG_TYPE_VFS,
	.vm_init = vfs_vm_init,
	.vm_deinit = vfs_vm_deinit,
	.reserve_cpu = vfs_reserve_cpu,
	.release_cpu = vfs_release_cpu,
};
