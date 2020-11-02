---
layout: post
title: "Lets warm up - picoCTF 2019"
author: gameplayone23
tags:
- General Skills
- 2020
- python
- ascii
---

# Lets warm up

- Category: General skills
- Points : 50

*"If I told you a word started with 0x70 in hexadecimal, what would it start with in ASCII?"*

# Solution

* Using `ASCII table` like this one :

![ASCII](/images/ascii_table.png)

* Using `python script` to convert the hex string to ASCII

```python
#!/usr/bin/env python

# Define a string without the 0x
hex_string="0x70"[2:]
# Convert to bytes object
bytes_object = bytes.fromhex(hex_string)
# Convert to ascii
ascii_string = bytes_object.decode("ASCII")

# Display the string
print(ascii_string)
```

displays :

```
p
```