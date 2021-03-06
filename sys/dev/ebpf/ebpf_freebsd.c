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

#include <sys/ebpf.h>
#include <sys/ebpf_function_idx.h>
#include <dev/ebpf/ebpf_platform.h>
#include <dev/ebpf/ebpf_internal.h>
#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_prog.h>

#include <sys/ebpf_probe.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/ktrace.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/wait.h>
#include <sys/unistd.h>

MALLOC_DECLARE(M_EBPFBUF);
MALLOC_DEFINE(M_EBPFBUF, "ebpf-buffers", "Buffers for ebpf and its subsystems");

static struct ebpf_module ebpf_mod_callbacks = {
	.fire = ebpf_fire,
	.clone_probe = ebpf_probe_clone,
	.release_probe = ebpf_probe_release,
};

/*
 * Platform dependent function implementations
 */
__inline void *
ebpf_malloc(size_t size)
{
	return malloc(size, M_EBPFBUF, M_NOWAIT);
}

__inline void *
ebpf_calloc(size_t number, size_t size)
{
	return malloc(number * size, M_EBPFBUF, M_NOWAIT | M_ZERO);
}

__inline void *
ebpf_exalloc(size_t size)
{
	return malloc(size, M_EBPFBUF, M_NOWAIT | M_EXEC);
}

__inline void
ebpf_exfree(void *mem, size_t size)
{
	free(mem, M_EBPFBUF);
}

__inline void
ebpf_free(void *mem)
{
	free(mem, M_EBPFBUF);
}

int
ebpf_error(const char *fmt, ...)
{
	int ret;
	__va_list ap;

	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);

	return ret;
}

__inline uint16_t
ebpf_ncpus(void)
{
	return mp_maxid + 1;
}

__inline uint16_t
ebpf_curcpu(void)
{
	return curcpu;
}

__inline long
ebpf_getpagesize(void)
{
	return PAGE_SIZE;
}

static epoch_t ebpf_epoch;

__inline void
ebpf_epoch_enter(void)
{
	epoch_enter(ebpf_epoch);
}

__inline void
ebpf_epoch_exit(void)
{
	epoch_exit(ebpf_epoch);
}

__inline void
ebpf_epoch_call(ebpf_epoch_context *ctx,
		void (*callback)(ebpf_epoch_context *))
{
	epoch_call(ebpf_epoch, ctx, callback);
}

__inline void
ebpf_epoch_wait(void)
{
	epoch_wait(ebpf_epoch);
}

__inline void
ebpf_mtx_init(ebpf_mtx *mutex, const char *name)
{
	mtx_init(mutex, name, NULL, MTX_DEF);
}

__inline void
ebpf_mtx_lock(ebpf_mtx *mutex)
{
	mtx_lock(mutex);
}

__inline void
ebpf_mtx_unlock(ebpf_mtx *mutex)
{
	mtx_unlock(mutex);
}

__inline void
ebpf_mtx_destroy(ebpf_mtx *mutex)
{
	mtx_destroy(mutex);
}

__inline void
ebpf_spinmtx_init(ebpf_spinmtx *mutex, const char *name)
{
	mtx_init(mutex, name, NULL, MTX_SPIN);
}

__inline void
ebpf_spinmtx_lock(ebpf_spinmtx *mutex)
{
	mtx_lock_spin(mutex);
}

__inline void
ebpf_spinmtx_unlock(ebpf_spinmtx *mutex)
{
	mtx_unlock_spin(mutex);
}

__inline void
ebpf_spinmtx_destroy(ebpf_spinmtx *mutex)
{
	mtx_destroy(mutex);
}

__inline void
ebpf_refcount_init(uint32_t *count, uint32_t value)
{
	refcount_init(count, value);
}

__inline void
ebpf_refcount_acquire(uint32_t *count)
{
	refcount_acquire(count);
}

__inline int
ebpf_refcount_release(uint32_t *count)
{
	return refcount_release(count);
}

__inline uint32_t
ebpf_jenkins_hash(const void *buf, size_t len, uint32_t hash)
{
	return jenkins_hash(buf, len, hash);
}

int
ebpf_init(void)
{
	ebpf_epoch = epoch_alloc("ebpf", 0);
	ebpf_module_register(&ebpf_mod_callbacks);
	return 0;
}

int
ebpf_deinit(void)
{
	ebpf_module_deregister();
	epoch_free(ebpf_epoch);
	return 0;
}

int
ebpf_fd_to_program(ebpf_thread *td, int fd, ebpf_file **fp_out, struct ebpf_prog **prog_out)
{
	int error;
	ebpf_file *fp;
	struct ebpf_obj_prog *prog;
	struct ebpf_obj *obj;

	error = ebpf_fget(td, fd, &fp);
	if (error != 0) {
		return (error);
	}

	if (!is_ebpf_objfile(fp)) {
		error = EINVAL;
		goto out;
	}

	obj = EBPF_OBJ(fp);
	if (obj->type != EBPF_OBJ_TYPE_PROG) {
		error = EINVAL;
		goto out;
	}

	prog = ebpf_obj_container_of(obj);

	*fp_out = fp;
	if (prog_out) {
		*prog_out = &prog->prog;
	}

	return (0);

out:
	if (fp != NULL) {
		ebpf_fdrop(fp, td);
	}

	return (error);
}

int
ebpf_probe_copyinstr(struct ebpf_vm_state *s, const void *uaddr, void *kaddr, size_t len, size_t *done)
{
	int error;

	error = copyinstr(uaddr, kaddr, len, done);
	curthread->td_errno = error;

	return (error);
}

int
ebpf_probe_copyin(struct ebpf_vm_state *s, const void *uaddr, void *kaddr, size_t size)
{
	int error;

	error = copyin(uaddr, kaddr, size);
	curthread->td_errno = error;

	return (error);
}

int
ebpf_probe_copyout(struct ebpf_vm_state *s, const void *kaddr, void *uaddr, size_t len)
{
	int error;

	error = copyout(kaddr, uaddr, len);
	curthread->td_errno = error;

	return (error);
}

int
ebpf_probe_dup(struct ebpf_vm_state *s, int fd)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_dup(td, FDDUP_NORMAL, 0, fd, 0);
	if (error != 0) {
		td->td_errno = error;
		return (-1);
	}

	/* Return the file descriptor. */
	return (td->td_retval[0]);
}

int
ebpf_probe_openat(struct ebpf_vm_state *s, int fd, const char * path, int flags, int mode)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_openat(td, fd, path, UIO_SYSSPACE, flags, mode);
	if (error != 0) {
		td->td_errno = error;
		return (-1);
	}

	/* Return the file descriptor. */
	return (td->td_retval[0]);
}

int
ebpf_probe_fstatat(struct ebpf_vm_state *s, int fd, const char *path, struct stat *sb, int flag)
{
	struct thread *td;
	int error;

	td = curthread;

	error = kern_statat(curthread, flag, fd, path, UIO_SYSSPACE, sb, NULL);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_fstat(struct ebpf_vm_state *s, int fd, struct stat *sb)
{
	struct thread *td;
	int error;

	td = curthread;

	error = kern_fstat(curthread, fd, sb);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_faccessat(struct ebpf_vm_state *s, int fd, const char *path, int mode, int flag)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_accessat(curthread, fd, path, UIO_SYSSPACE, flag, mode);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_set_errno(struct ebpf_vm_state *s, int error)
{

	curthread->td_errno = error;
	return (0);
}

int
ebpf_probe_get_errno(struct ebpf_vm_state *s)
{

	return (curthread->td_errno);
}

int
ebpf_probe_set_syscall_retval(struct ebpf_vm_state *s, int ret0, int ret1)
{
	struct thread *td;

	td = curthread;
	td->td_retval[0] = ret0;
	td->td_retval[1] = ret1;
	return (0);
}


pid_t
ebpf_probe_pdfork(struct ebpf_vm_state *s, int *fd, int flags)
{
	struct thread *td;
	struct fork_req fr;
	int error, pid;

	bzero(&fr, sizeof(fr));
	fr.fr_flags = RFFDG | RFPROC | RFPROCDESC;
	fr.fr_pidp = &pid;
	fr.fr_pd_fd = fd;
	fr.fr_pd_flags = flags;

	td = curthread;
	error = fork1(td, &fr);
	if (error != 0) {
		td->td_errno = error;
		return (-1);
	}

	return (pid);
}

static int
ebpf_probe_do_pdwait(int fd, int* status, int options, struct rusage *ru)
{
	int error;
	struct thread *td;

	td = curthread;
	error = kern_pdwait4(td, fd, status, options, ru);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_pdwait4_nohang(struct ebpf_vm_state *s, int fd, int* status, int options, struct rusage *ru)
{

	/*
	 * We cannot block here as the process that we block on could block on
	 * us holding the ebpf state lock, leading to a deadlock.
	 */
	options |= WNOHANG;

	return (ebpf_probe_do_pdwait(fd, status, options, ru));
}

static void
ebpf_probe_do_deferred_pdwait4(struct ebpf_vm_state *s)
{
	int error, status;

	status = 0;
	bzero(&s->scratch.wait4.rusage, sizeof(s->scratch.wait4.rusage));

	error = ebpf_probe_do_pdwait(s->scratch.wait4.fd, &status,
	    s->scratch.wait4.options, &s->scratch.wait4.rusage);

	s->next_vm_args[0] = (uintptr_t)s->scratch.wait4.arg;
	s->next_vm_args[1] = error;
	s->next_vm_args[2] = status;
	s->next_vm_args[3] = (uintptr_t)&s->scratch.wait4.rusage;
	s->next_vm_args[4] = s->scratch.wait4.fd;
	s->num_args = 5;
}

int
ebpf_probe_pdwait4_defer(struct ebpf_vm_state *s, int fd, int options, void *arg,
    void *next)
{
	struct ebpf_prog *prog;
	int *prog_fd;
	int error;

	prog_fd = next;
	if (prog_fd == NULL) {
		curthread->td_errno = ENOENT;
		return (ENOENT);
	}

	error = ebpf_fd_to_program(ebpf_curthread(), *prog_fd, &s->vm_fp, &prog);
	if (error != 0) {
		curthread->td_errno = error;
		return (error);
	}

	s->scratch.wait4.fd = fd;
	s->scratch.wait4.options = options;
	s->scratch.wait4.arg = arg;

	s->next_vm = prog->vm;
	s->deferred_func = ebpf_probe_do_deferred_pdwait4;
	return 0;
}

/*
 * XXX a comment in kern_exec.c claims that kern_execve can call exit1() and
 * fail to return.  If this happens we will leak EBPF locks.
 */
int
ebpf_probe_fexecve(struct ebpf_vm_state *s, int fd, char ** argv,
    char ** envp, char ** argv_prepend)
{
	struct thread *td;
	struct image_args args;
	struct vmspace *oldvmspace;
	int error;

	td = ebpf_curthread();

	error = pre_execve(td, &oldvmspace);
	if (error != 0) {
		td->td_errno = error;
		return (error);
	}

	error = exec_copyin_args_prepend(&args, NULL, UIO_SYSSPACE,
	    argv, envp, argv_prepend);
	if (error != 0) {
		td->td_errno = error;
		return (error);
	}

	args.fd = fd;
	error = kern_execve(td, &args, NULL);
	td->td_errno = error;

	post_execve(td, error, oldvmspace);
	return (error);
}

int
ebpf_probe_readlinkat(struct ebpf_vm_state *s, int fd, const char *path,
    char *buf, size_t bufsize)
{
	struct thread *td;
	int error;

	td = ebpf_curthread();
	error = kern_readlinkat(td, fd, path, UIO_SYSSPACE, buf, UIO_SYSSPACE, bufsize);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

void *
ebpf_probe_memset(struct ebpf_vm_state *s, void *mem , int c, size_t size)
{

	return (memset(mem, c, size));
}

int
ebpf_probe_exec_get_interp(struct ebpf_vm_state *s, int fd, char *buf,
    size_t bufsize, int *type)
{
	struct thread *td;
	int error;

	td = ebpf_curthread();
	error = exec_get_interp(td, fd, buf, bufsize, type);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_strncmp(struct ebpf_vm_state *s, const char *a, const char *b,
    size_t len)
{

	return (strncmp(a, b, len));
}

static void
path_strip_trailing_slashes(char * path, size_t *base_idx)
{
	size_t i;

	/*
	 * This deliberately does not remove a / at the start of path, because
	 * "/" is a valid canonical path.
	 */
	i = *base_idx;
	while (i > 1 && path[i - 1] == '/') {
		path[i - 1] = '\0';
		--i;
	}

	*base_idx = i;
}

static int
path_strip_last_comp(char * path, size_t *base_idx)
{
	size_t i;

	path_strip_trailing_slashes(path, base_idx);

	i = *base_idx;
	if (i == 0 || (i == 1 && path[0] == '/')) {
		// .. went outside of path; error
		return (EINVAL);
	}

	--i;
	while (path[i] != '/') {
		path[i] = '\0';
		if (i == 0) {
			break;
		}
		--i;
	}

	*base_idx = i + 1;
	return (0);
}

static int
make_canonical(char *base, const char * rela, size_t bufsize)
{
	int error;
	char ch;
	size_t base_idx, i, last_slash;

	if (rela[0] == '/') {
		memset(base, 0, bufsize);
		base_idx = 0;

		if (rela[1] == '\0') {
			base[0] = '/';
			base[1] = '\0';
			return (0);
		}
		last_slash = 0;
	} else {
		base_idx = strlen(base);
		if (base[base_idx - 1] != '/') {
			base[base_idx] = '/';
			base_idx++;
			if (base_idx == bufsize) {
				return (ENAMETOOLONG);
			}
		}
		last_slash = 1;
	}

	for (i = 0; i < bufsize; ++i) {
next:
		if (rela[i] == '\0') {
			if (base_idx == 0) {
				base[base_idx] = '/';
				++base_idx;
				if (base_idx == bufsize) {
					return (ENAMETOOLONG);
				}
			}
			base[base_idx] = '\0';
			return (0);

		} else if ((i + 1) < bufsize && rela[i] == '.' && rela[i+1] == '.') {
			error = path_strip_last_comp(base, &base_idx);
			if (error != 0) {
				return error;
			}

			last_slash = 1;

		} else if (rela[i] == '.' &&
		    (((i + 1) == bufsize) || (rela[i+1] == '/' || rela[i+1] == '\0'))) {
			/* Skip over "." path components */
			continue;

		} else if (rela[i] == '/') {
			if (!last_slash) {
				base[base_idx] = '/';
				++base_idx;
				if (base_idx == bufsize) {
					return (ENAMETOOLONG);
				}
				last_slash = 1;
			}
		} else {
			last_slash = 0;
			do  {
				ch = rela[i];
				if (ch == '\0' || ch == '/') {
					goto next;
				}
				++i;

				base[base_idx] = ch;
				++base_idx;
				if (base_idx == bufsize) {
					return (ENAMETOOLONG);
				}
			} while (i < bufsize);
		}

	}

	return (ENAMETOOLONG);
}

int
ebpf_probe_canonical_path(struct ebpf_vm_state *s, char *base,
    const char * rela, size_t bufsize)
{

	return (make_canonical(base, rela, bufsize));
}

int
ebpf_probe_renameat(struct ebpf_vm_state *s, int fromfd, const char *from,
    int tofd, const char *to)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_renameat(td, fromfd, from, tofd, to, UIO_SYSSPACE);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_mkdirat(struct ebpf_vm_state *s, int fd, const char *path,
    mode_t mode)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_mkdirat(td, fd, path, UIO_SYSSPACE, mode);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_fchdir(struct ebpf_vm_state *s, int fd)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_fchdir(td, fd);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

pid_t
ebpf_probe_getpid(struct ebpf_vm_state *s)
{

	return (curthread->td_proc->p_pid);
}

int
ebpf_probe_ktrnamei(struct ebpf_vm_state *s, char *path)
{

	ktrnamei(path);
	return (0);
}

static int
do_symlink_path(char *base, const char * rela, size_t bufsize)
{
	size_t base_idx;
	int error;

	if (rela[0] != '/') {
		base_idx = strlen(base);

		error = path_strip_last_comp(base, &base_idx);
		if (error != 0) {
			return (error);
		}
	}

	return (make_canonical(base, rela, bufsize));
}

int
ebpf_probe_symlink_path(struct ebpf_vm_state *s, char *base,
    const char * rela, size_t bufsize)
{

	return (do_symlink_path(base, rela, bufsize));
}

size_t
ebpf_probe_strlcpy(struct ebpf_vm_state *s, char *dest,
    const char * src, size_t bufsize)
{

	return (strlcpy(dest, src, bufsize));
}

int
ebpf_probe_kqueue(struct ebpf_vm_state *s, int uflags)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_kqueue(td, 0, NULL, uflags);
	if (error != 0) {
		td->td_errno = error;
		return (-1);
	}

	return (td->td_retval[0]);
}

static int
ebpf_kevent_copyout(void *arg, struct kevent *kevp, int count)
{

	memcpy(arg, kevp, sizeof(*kevp) * count);
	return (0);
}

static int
ebpf_kevent_copyin(void *arg, struct kevent *kevp, int count)
{

	memcpy(kevp, arg, sizeof(*kevp) * count);
	return (0);
}

static void
ebpf_init_kops(struct kevent_copyops *k_ops, void *arg)
{

	k_ops->arg = arg;
	k_ops->k_copyout = ebpf_kevent_copyout,
	k_ops->k_copyin = ebpf_kevent_copyin,
	k_ops->kevent_size = sizeof(struct kevent);
}

int
ebpf_probe_kevent_install(struct ebpf_vm_state *s, int kq, struct kevent *ev,
    int num)
{
	struct kevent_copyops k_ops;
	struct thread *td;
	int error;

	td = curthread;
	ebpf_init_kops(&k_ops, ev);
	error = kern_kevent(td, kq, num, 0, &k_ops, NULL);
	if (error != 0) {
		td->td_errno = error;
		return (-1);
	}

	return (td->td_retval[0]);
}

int
ebpf_probe_kevent_poll(struct ebpf_vm_state *s, int kq, struct kevent *ev,
    int num)
{
	struct kevent_copyops k_ops;
	struct timespec timeout = {0, 0};
	struct thread *td;
	int error;

	td = curthread;
	ebpf_init_kops(&k_ops, ev);
	error = kern_kevent(td, kq, 0, num, &k_ops, &timeout);
	if (error != 0) {
		td->td_errno = error;
		return (-1);
	}

	return (td->td_retval[0]);
}

static void
ebpf_probe_do_deferred_kevent(struct ebpf_vm_state *s)
{
	struct kevent_copyops k_ops;
	struct thread *td;
	struct timespec *timeout;
	int error;

	td = curthread;
	bzero(&s->scratch.kevent.ev, sizeof(s->scratch.kevent.ev));
	ebpf_init_kops(&k_ops, &s->scratch.kevent.ev);
	if (s->scratch.kevent.ts_valid) {
		timeout = &s->scratch.kevent.ts;
	} else {
		timeout = NULL;
	}
	error = kern_kevent(td, s->scratch.kevent.kq, 0, 1, &k_ops, timeout);

	/* s->next_vm_args[0] remains the same. */
	s->next_vm_args[1] = error;
	s->next_vm_args[2] = (uintptr_t)&s->scratch.kevent.ev;
	s->num_args = 3;
}


int
ebpf_probe_kevent_block(struct ebpf_vm_state *s, int kq,
    const struct timespec *ts, void *next)
{
	struct ebpf_prog *prog;
	int *prog_fd;
	int error;

	prog_fd = next;
	if (prog_fd == NULL) {
		curthread->td_errno = ENOENT;
		return (ENOENT);
	}

	error = ebpf_fd_to_program(ebpf_curthread(), *prog_fd, &s->vm_fp, &prog);
	if (error != 0) {
		curthread->td_errno = error;
		return (error);
	}

	s->scratch.kevent.kq = kq;
	if (ts != NULL) {
		s->scratch.kevent.ts_valid = 1;
		s->scratch.kevent.ts = *ts;
	} else {
		s->scratch.kevent.ts_valid = 0;
	}

	s->next_vm = prog->vm;
	s->deferred_func = ebpf_probe_do_deferred_kevent;
	return (0);
}

int
ebpf_probe_close(struct ebpf_vm_state *s, int fd)
{
	int error;
	struct thread *td;

	td = curthread;
	error = kern_close(td, fd);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_get_syscall_retval(struct ebpf_vm_state *s)
{

	return (curthread->td_retval[0]);
}

int
ebpf_probe_symlinkat(struct ebpf_vm_state *s, const char *target, int fd,
    const char *source)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_symlinkat(td, target, fd, source, UIO_SYSSPACE);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

static int
find_next_slash(const char * str, int start)
{

	while (str[start] != '\0') {
		if (str[start] == '/') {
			return start;
		}

		++start;
	}

	return (-1);
}

int
ebpf_probe_resolve_one_symlink(struct ebpf_vm_state *s,
    struct ebpf_symlink_res_bufs *buffers, int fd, char *fileName,
    int flags)
{
	struct thread *td;
	int i, sep_pos, error;
	char *target;
	char *path_suffix;

	td = curthread;
	target = buffers->scratch1;
	path_suffix = buffers->scratch2;

	bzero(target, MAXPATHLEN);

	i = 0;
	while (1) {
		sep_pos = find_next_slash(fileName, i);
		if (sep_pos >= 0) {
			fileName[sep_pos] = '\0';
		} else {
			if (flags & AT_SYMLINK_NOFOLLOW) {
				return (ENODEV);
			}
		}

		error = kern_readlinkat(td, fd, fileName, UIO_SYSSPACE, target,
		    UIO_SYSSPACE, MAXPATHLEN);
		if (error != 0 && error != EINVAL) {
			td->td_errno = error;
			return (error);
		}

		if (error == 0) {
			if (sep_pos >= 0) {
				strlcpy(path_suffix, &fileName[sep_pos + 1],
				    MAXPATHLEN);
			} else {
				path_suffix[0] = '\0';
			}
			break;
		}

		if (sep_pos < 0) {
			return (ENODEV);
		}

		fileName[sep_pos] = '/';
		i = sep_pos + 1;
	}

	error = do_symlink_path(buffers->pathBuf, target, MAXPATHLEN);
	if (error != 0 || path_suffix[0] == '\0') {
		return (error);
	}

	return (make_canonical(buffers->pathBuf, path_suffix, MAXPATHLEN));
}


int
ebpf_probe_utimensat(struct ebpf_vm_state *s, int fd, const char * file,
    struct timespec *times, int flag)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_utimensat(td, fd, file, UIO_SYSSPACE, times, UIO_SYSSPACE, flag);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_fcntl(struct ebpf_vm_state *s, int fd, int cmd, int arg)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_fcntl(td, fd, cmd, arg);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_unlinkat(struct ebpf_vm_state *s, int fd, const char * path, int flags)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_funlinkat(td, fd, path, FD_NONE, UIO_SYSSPACE, flags, 0);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_fchown(struct ebpf_vm_state *s, int fd, uid_t uid, gid_t gid)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_fchown(td, fd, uid, gid);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_fchownat(struct ebpf_vm_state *s, int fd, const char * file,
    uid_t uid, gid_t gid, int flag)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_fchownat(td, fd, file, UIO_SYSSPACE, uid, gid, flag);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_fchmod(struct ebpf_vm_state *s, int fd, mode_t mode)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_fchmod(td, fd, mode);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_fchmodat(struct ebpf_vm_state *s, int fd, const char * file,
    mode_t mode, int flag)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_fchmodat(td, fd, file, UIO_SYSSPACE, mode, flag);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_futimens(struct ebpf_vm_state *s, int fd, struct timespec *times)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_futimens(td, fd, times, UIO_SYSSPACE);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

int
ebpf_probe_linkat(struct ebpf_vm_state *s, int fromfd, const char *from,
    int tofd, const char *to, int flag)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_linkat(td, fromfd, tofd, from, to, UIO_SYSSPACE, flag);
	if (error != 0) {
		td->td_errno = error;
	}

	return (error);
}

/*
 * Kernel module operations
 */
static int
ebpf_loader(__unused struct module *module, int event, __unused void *arg)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
		error = ebpf_init();
		break;
	case MOD_UNLOAD:
		error = ebpf_deinit();
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

DEV_MODULE(ebpf, ebpf_loader, NULL);
MODULE_VERSION(ebpf, 1);
