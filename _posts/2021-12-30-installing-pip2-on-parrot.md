---
layout: post
comments: true
title:  "Installing pip2 on ParrotOS"
tags: ['parrot', 'python2']
---

I was practicing my skills at [HackTheBox](https://www.hackthebox.com/) and I got a problem,
python2 (therefore pip2) are officially not longer supported on ParrotOS and Kali.
Well, thats a big problem because most of the well-know scripts and tools are written in python2.
In addition they removed pip2 package from the official repositories so you hace to install it by your own.
>Because python2 is not longer supported maybe in later versions having python2/pip2 installed in your system could potencially break it. Do this at your own risk!

```bash
sudo apt install python2
curl https://bootstrap.pypa.ip/pip/2.7/get-pip.py -o get-pip.py
sudo python2 get-pip.py
```
<br>

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