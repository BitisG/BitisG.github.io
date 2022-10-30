---
title: Tar and Feathers - FE-CTF 2022 writeup
date: 2022-10-30 13:38:00 +0200
categories: [Writeup, CTF]
tags: ["forensics"]     # TAG names should always be lowercase
img_path: /assets/img/ctf/fe/
image: # Thumbnail 
  src: tar_chall.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Summary
This challenge revolves around extracting a bunch of layers from a `tar` archive, and then rearranging those layers into other files. In short, someone at FE got creative with their use of tar :) 

## Extracting all layers of the first archive
We are given a file, `tar-and-feathers.tgz`, which is a POSIX tar archive. Trying to extract from the archive results in a new archive named something like `25` and so on. We quickly realised that the name of each layer represented a hex value. Our idea was then to fully extract all layers from the original archive, and then assemble all the hex values we are given into a new file. Of course we need to also make sure that we get the order of the layers right when creating the new file. For extraction we used this quick and dirty script:
```shell
#!/bin/bash

found=1
next='tar-and-feathers.tgz'

while [[ ${found} -eq 1 ]]; do
    echo "Untaring - $next"
    tmp=$(tar -tf $next)
    tar -tf $next>>file
    tar -xf $next
    next=$tmp

done
exit 0
```

This script extracts all the layers, while adding the names of the layers into a file. 

We can then write all these bytes to a file, resulting in a new tar archive, which contains these files:
```
E2.tar  offsets.py  runme.py*  tar-and-feathers.tgz  top.png
```

## The challenge in layer 2

The source of `runme.py` can be found below:
```python
#!/usr/bin/env python3
import os
import sys
import subprocess
from offsets import offsets

if len(sys.argv) != 2:
    print(f'Usage: {sys.argv[0]} <outfile>', file=sys.stderr)
    exit(-1)

INIT = 'tar-and-feathers.tgz'

def run(cmd):
    return subprocess.check_output(cmd, shell=True)

def unpack1(name):
    filemagic = run(f'file {name}')
    if b'bzip2' in filemagic:
        run(f'mv {name} {name}.bz2')
        run(f'bunzip2 {name}.bz2')
        return unpack1(name)
    return run(f'tar xfv {name}').strip().decode()

def getbyte(n):
    print(f'getbyte({n}) = ', end='', file=sys.stderr, flush=True)
    prev = None
    for _ in range(n + 1):
        next = unpack1(prev or INIT)
        if prev and prev != next:
            os.unlink(prev)
        try:
            byte = int(next, 16)
        except:
            os.unlink(next)
            raise
        prev = next
    os.unlink(next)
    print(f'0x{byte:02x}', file=sys.stderr)
    return byte

def unpack(path):
    data = bytes(getbyte(offset) for offset in offsets)
    with file(path, 'wb') as fd:
        fd.write(data)

unpack(sys.argv[1])
```

`runme.py` seems to be a script that extracts each layer of the original tar archive, until it reaches a specific layer or offset, and then prints that layers name as a byte. It does this for each of the offsets in the `offsets` file, meaning it takes ages for it to run, and we would probably still be waiting on this script to be done if we hadn't optimized it. We basically this script, found the highest offset, ran it once looking for that offset and wrote all the extracted layer names to a file.

Modified `runme.py`:

```python
#!/usr/bin/env python3
import os
import sys
import subprocess
from offsets import offsets

if len(sys.argv) != 2:
    print(f'Usage: {sys.argv[0]} <outfile>', file=sys.stderr)
    exit(-1)

INIT = 'tar-and-feathers.tgz'

def run(cmd):
    return subprocess.check_output(cmd, shell=True)

def unpack1(name):
    filemagic = run(f'file {name}')
    if b'bzip2' in filemagic:
        run(f'mv {name} {name}.bz2')
        run(f'bunzip2 {name}.bz2')
        return unpack1(name)
    return run(f'tar xfv {name}').strip().decode()

def getbyte(n):
    print(f'getbyte({n}) = ', end='', file=sys.stderr, flush=True)
    prev = None
    with open("outfile", 'w') as fd:
        for _ in range(n + 1):
            next = unpack1(prev or INIT)
            if prev and prev != next:
                os.unlink(prev)
            try:
                byte = int(next, 16)
            except:
                os.unlink(next)
                raise
            prev = next
            fd.write(next+'\n')
    os.unlink(next)
    print(f'0x{byte:02x}', file=sys.stderr)
    return byte

def unpack(path):
    data = bytes(getbyte(50382))

unpack(sys.argv[1])
```

We then created the script below so that instead of extracting all the layers it simply looked up the value of the layer in an array, and wrote the bytes to a file named `output`:

```python
from offsets import offsets
import binascii

with open("outfile", "r") as f:
	l = f.readlines()

for i,line in enumerate(l):
	l[i] = line.strip()

print(l)

with open ("output", "wb") as f:
	for offset in offsets:
		f.write(binascii.unhexlify(l[offset]))
```

This gets you a pdf:

![Extracted png](pdf.png)

While text in the pdf has been "redacted" by putting a black bar over it, the text is still in the file and can be extracted via the following:
```console
bitis@Workstation ~/c/f/t/_file_decoded.extracted> pdftotext download-1.pdf && cat download-1.txt
flag{it’s turtles all the way down}

1
```

