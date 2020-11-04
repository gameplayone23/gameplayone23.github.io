---
layout: post
title: "Pitter, patter, platters - picoCTF 2019"
author: gameplayone23
tags:
- forensics
- 2020
- Autopsy
---

# Pitter, patter, platters

- Category: Forensics

*"'Suspicious' is written all over this disk image. Download suspicious.dd.sda1"*

# Multiple Fails

`Hint 1` : It may help to analyze this image in multiple ways: as a blob, and as an actual mounted disk.
`Hint 2` : Have you heard of [slack space](https://www.computerhope.com/jargon/s/slack-space.htm)? There is a certain set of tools that now come with Ubuntu that I'd recommend for examining that disk space phenomenon...

Working in WSL, i tried to mount the disk but got an "operation not permitted".

Then i looked at the the following carving tool :

- [Scalpel](https://linux.die.net/man/1/scalpel)

- [Foremost](https://linux.die.net/man/1/foremost)

I was able to find the file "suspicious-file.txt". But once extracted, i couldn't find any data in the slack space ?!`

# Solution

So i went to read a [writeup](https://xploiter.medium.com/pitter-patter-platters-picoctf2020-writeup-fe30a45b5f5c) in which the author used [Autopsy](https://www.sleuthkit.org/autopsy/) a software based on the `TSK suite`.

I was able to follow his instructions and found the flag.

But i wanted to know which software were used.

So i went to see Autopsy's log and found the binaries and parameters :

`fls` is used to list the files in this case in the root directory (inode : 2)

```
'/usr/bin/fls' -f ext -la  -s '0' -o 0 -i raw '/var/lib/autopsy/suspicious/host1/images/suspicious.dd.sda1' 2
```

![fls](/images/pitter_fls.png)

Then `istat` is used to find the data block number where the file (inode : 12) is stored.

```
'/usr/bin/istat' -f ext  -s '0' -o 0 -i raw '/var/lib/autopsy/suspicious/host1/images/suspicious.dd.sda1' 12
```

![istat](/images/pitter_istat.png)

Finally `blkcat` displays the data of the block.

```
'/usr/bin/blkcat' -f ext  -a -o 0 -i raw '/var/lib/autopsy/suspicious/host1/images/suspicious.dd.sda1' 2049 1
```

![blkcat](/images/pitter_blkcat.png)

# Conclusion
i'v got a better understanding of the methology and how a filesystem works. But i need to go back to my failures to see if those softwares could have worked.
