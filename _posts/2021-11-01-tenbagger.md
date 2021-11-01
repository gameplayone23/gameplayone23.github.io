---
layout: post
title: "Tenbagger - Hack.lu CTF"
author: gameplayone23
tags:
- 2021
- pcap
- scapy
- wireshark
---

# Tenbagger

- Category: Misc

# Description

```
I think I took it too far and made some trades and lost everything. My only chance to fix my account balance is a tenbagger.
```

# PCAP

The file provided is a pcap file. Openning it with wireshark we can see FIX protocol :

![Wireshark](/images/tenbagger_wireshark.png)

The flag is contained in the field `58`

# Code

Using python and `scapy`, we can extract the flag :

```python
from scapy.all import *

# Load pcap file
packets = rdpcap('tenbagger.pcapng')

# Init flag
flag = ''

# Loop through packets
for p in packets:
    if p.haslayer(Raw):
        try:
            # Example of line : 
            # b'8=FIX.4.4\x019=131\x0135=D\x0149=BUYSIDE\x0156=SELLSIDE\x0134=2\x0152=20211029-15:26:40.067\x0160=20211029-15:26:40.067\x0111=CAFEBABE\x0155=FLX\x0138=2\x0140=1\x0154=1\x0144=1337\x0158=fl\x0110=021\x01'
            
            # Split raw layer
            payload_fields = p.load.split(b'\x01')
            # Check if FIX protocol and ORDER SINGLE type
            if payload_fields[0] == b'8=FIX.4.4' and payload_fields[2] == b'35=D':
                # Get flag part in TEXT field => "55=XXX"
                flag += payload_fields[14].decode().split("=")[1]
        except:
            pass
print(f"FLAG : {flag}")
```

# Conclusion

`Scapy` is a powerful tool, i need to dig in it.