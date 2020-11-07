---
layout: post
title: "SSE_KEYGENME - KAF 2020"
author: gameplayone23
tags:
- General skills
- 2020
- Reversing
- Angr
---

# SSE_KEYGENME

- Category: Reversing
- Points : 500

*"Like in the good old days, but faster."*

# Executable

First, let's execute :

```bash
./SSE_KEYGENME
###############################
### WELCOME TO SSE_KEYGENME ###
###      ENJOY YOUR STAY    ###
###############################
Enter key:
> MYKEY
Wrong key, try again...
```

I fired up Ghidra and looked at the disassembly of the main function :

```c
undefined8 main(void)

{
  int iVar1;
  long lVar2;
  long in_FS_OFFSET;
  undefined local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("###############################");
  puts("### WELCOME TO SSE_KEYGENME ###");
  puts("###      ENJOY YOUR STAY    ###");
  puts("###############################");
  printf("Enter key:\n> ");
  lVar2 = get_input(local_38,0x20);
  if (lVar2 == 0) {
    puts("Please enter a key.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  pad(local_38,lVar2,0x20,lVar2);
  iVar1 = check_login(local_38,0x20,0x20);
  if (iVar1 == 0) {
    puts("Wrong key, try again...");
  }
  else {
    puts("Success! Enjoy the rest of the competition :)");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So the input is submitted to the `check_login` function :

```c
undefined8 check_login(long param_1,ulong param_2)

{
  undefined auVar1 [16];
  undefined auVar2 [16];
  undefined auVar3 [16];
  void *__ptr;
  ulong local_100;
  ulong local_f8;
  
  if ((param_2 & 0xf) != 0) {
    puts("Input size not multiple of block length, exiting...");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  __ptr = malloc(param_2);
  local_100 = 0;
  while (local_100 < param_2) {
    auVar3 = vmovaps_avx(CONCAT88(0x101010101010101,0x101010101010101));
    auVar3 = vmovaps_avx(auVar3);
    auVar1 = vlddqu_avx((undefined  [16])0x3060c010e050702);
    auVar1 = vmovaps_avx(auVar1);
    auVar2 = vlddqu_avx((undefined  [16])0x13110d0b07050302);
    auVar2 = vmovaps_avx(auVar2);
    auVar1 = vmovaps_avx(auVar1);
    auVar1 = vmovaps_avx(auVar1);
    auVar3 = vmovaps_avx(auVar3);
    auVar3 = vmovaps_avx(auVar3);
    auVar1 = vmovaps_avx(auVar1);
    auVar3 = vmovaps_avx(auVar3);
    auVar3 = vpsubb_avx(auVar1,auVar3);
    auVar3 = vmovaps_avx(auVar3);
                    /* WARNING: Load size is inaccurate */
    auVar1 = vlddqu_avx(*(undefined *)(local_100 + param_1));
    auVar1 = vmovaps_avx(auVar1);
    auVar1 = vmovaps_avx(auVar1);
    auVar1 = vmovaps_avx(auVar1);
    auVar3 = vmovaps_avx(auVar3);
    auVar3 = vmovaps_avx(auVar3);
    auVar3 = vmovaps_avx(auVar3);
    auVar1 = vmovaps_avx(auVar1);
    auVar3 = vpshufb_avx(auVar1,auVar3);
    auVar3 = vmovaps_avx(auVar3);
    auVar3 = vmovaps_avx(auVar3);
    auVar3 = vmovaps_avx(auVar3);
    auVar1 = vmovaps_avx(auVar2);
    auVar1 = vmovaps_avx(auVar1);
    auVar3 = vmovaps_avx(auVar3);
    auVar1 = vmovaps_avx(auVar1);
    auVar3 = vxorps_avx(auVar3,auVar1);
    auVar3 = vmovaps_avx(auVar3);
    auVar3 = vmovaps_avx(auVar3);
    auVar3 = vmovaps_avx(auVar3);
    auVar3 = vmovaps_avx(auVar3);
                    /* WARNING: Store size is inaccurate */
    *(undefined *)(local_100 + (long)__ptr) = auVar3;
    local_100 = local_100 + 0x10;
  }
  local_f8 = 0;
  while( true ) {
    if (param_2 <= local_f8) {
      free(__ptr);
      return 1;
    }
    if (*(char *)(local_f8 + (long)__ptr) != (&flag)[local_f8]) break;
    local_f8 = local_f8 + 1;
  }
  free(__ptr);
  return 0;
}
```

In this function, the input is processed with instruction beyound my knowledge and compared to `flag`:

```
                             flag                                            XREF[2]:     check_login:00100c12(*), 
                                                                                          check_login:00100c23(R)  
        00100e40 43              ??         43h    C
        00100e41 51              ??         51h    Q
        00100e42 43              ??         43h    C
        00100e43 36              ??         36h    6
        00100e44 40              ??         40h    @
        00100e45 52              ??         52h    R
        00100e46 21              ??         21h    !
        00100e47 55              ??         55h    U
        00100e48 24              ??         24h    $
        00100e49 42              ??         42h    B
        00100e4a 5b              ??         5Bh    [
        00100e4b 68              ??         68h    h
        00100e4c 7d              ??         7Dh    }
        00100e4d 67              ??         67h    g
        00100e4e 1f              ??         1Fh
        00100e4f 7b              ??         7Bh    {
        00100e50 5d              ??         5Dh    ]
        00100e51 7e              ??         7Eh    ~
        00100e52 4e              ??         4Eh    N
        00100e53 0e              ??         0Eh
        00100e54 58              ??         58h    X
        00100e55 04              ??         04h
        00100e56 22              ??         22h    "
        00100e57 40              ??         40h    @
        00100e58 1e              ??         1Eh
        00100e59 14              ??         14h
        00100e5a 16              ??         16h

```

# Solution

SO, following a Google CTF writeup, i decided to use `Angr`. The goal is to access to this address :

```
        00100d41 48 8d 3d        LEA        RDI,[s_Success!_Enjoy_the_rest_of_the_c_00100f   = "Success! Enjoy the rest of th
                 08 02 00 00
        00100d48 e8 53 f9        CALL       puts                                             int puts(char * __s)
                 ff ff

```


And avoid this one :

```
                             LAB_00100d4f                                    XREF[1]:     00100d3f(j)  
        00100d4f 48 8d 3d        LEA        RDI,[s_Wrong_key,_try_again..._00100f7e]         = "Wrong key, try again..."
                 28 02 00 00
        00100d56 e8 45 f9        CALL       puts                                             int puts(char * __s)
                 ff ff
```

Here the python script using `angr` :

```python
import angr
import sys
import claripy

FLAG_LEN = 23 # Input length without the newline
STDIN_FD = 0 
base_addr = 0x100000 # Base address found with Ghidra
our_binary = './SSE_KEYGENME'

# Initialize a project with our binary and base address
proj = angr.Project(our_binary, main_opts={'base_addr': base_addr}) 

# Generate our input with <FLAG_LEN> BVS et ONE BVV for the new line
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(FLAG_LEN)]
flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')]) 

# Initialize a state with our binary, dynamic input and unicorn
state = proj.factory.full_init_state(
        args=[our_binary],
        add_options=angr.options.unicorn,
        stdin=flag,
)

# Add contraints to the dynamic input using only printable characters
for k in flag_chars:
    state.solver.add(k >= ord('!'))
    state.solver.add(k <= ord('~'))

# Create a simulation manager with our state
simgr = proj.factory.simulation_manager(state)

# Note : I tried to use addresses of sucess and failure but it wasn't working, so i came up with this functions parsing the screen output
# Success function
def is_successful(state):
	output = state.posix.dumps(sys.stdout.fileno())
	if b'Success' in output: 
		return True
	return False

# Failure function
def is_ko(state):
	output = state.posix.dumps(sys.stdout.fileno())
	if b'Wrong' in output:
		return True
	return False

# Start exploration using our guidance
simgr.explore(find=is_successful, avoid=is_ko)

# Display the flag
if (len(simgr.found) > 0):
    for found in simgr.found:
        print(found.posix.dumps(STDIN_FD).decode())
```

Displays :

```
KAF{F0R_0LD_T1M3S_S4K3}
```

# Conclusion

With `angr`, no need to understand the entire binary code. You provide the input format, success and failure and it finds the path by itself, prettry neat.