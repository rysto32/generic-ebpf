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

enum ebpf_common_functions {
	EBPF_FUNC_unspec = 0,
	EBPF_FUNC_ebpf_map_update_elem,
	EBPF_FUNC_ebpf_map_lookup_elem,
	EBPF_FUNC_ebpf_map_delete_elem,
	EBPF_FUNC_ebpf_map_lookup_path,
	EBPF_FUNC_copyinstr,
	EBPF_FUNC_copyout,
	EBPF_FUNC_dup,
	EBPF_FUNC_openat,
	EBPF_FUNC_fstatat,
	EBPF_FUNC_fstat,
	EBPF_FUNC_faccessat,
	EBPF_FUNC_set_errno,
	EBPF_FUNC_set_syscall_retval,
	EBPF_FUNC_pdfork,
	EBPF_FUNC_pdwait4_nohang,
	EBPF_FUNC_pdwait4_defer,
	EBPF_FUNC_fexecve,
	EBPF_FUNC_memset,
	EBPF_FUNC_readlinkat,
	EBPF_FUNC_dummy_unimpl,
	EBPF_FUNC_exec_get_interp,
	__EBPF_COMMON_FUNCTIONS_MAX
};
