---
layout: post
comments: true
title: "Storing API credentials on Python"
tags: ['good-practice','Python','cryptography']
---

## Introduction

As we work with APIs we need to use some credentials to interact with them. These credentials can be stored in a safe way or not.
In this post we are going to cover the most popular practices to handle sensitive credentials from worst to best.

## Bad practices

* Harcoding credentials: 
    By far the worst practice anyone can use trying to interact with an API.
    If an attacker can somehow read the Python code file, he could get the credentials to read, write or delete sensitive data.
    ```python
    password = "non_super_secret_password"
    # Using the password in the API...
    ```

* Encoding credentials: 
    The only reason this practice is not qualificated as the  most **devilish** is because *harcoding credentials* exists.
    Encoding credentials does not secure them at all. This is a way to transform a string into another format, and it happens to be extremely easy to figure out what format has been used to encode and then decode it back to the plain text string.
    ```python
    import base64
    password = "bm9uX3N1cGVyX3NlY3JldF9wYXNzd29yZA=="
    uncoded_pass_bytes = base64.b64decode(password)
    uncoded_pass = uncoded_pass_bytes.decode('ascii')
    # Using the uncoded_pass in the API...
    ```

## Good practices

* Storing credentiales in plain text files: 
    A better aproach for storing API credentials is creating a file with the user and password you need. If we are using git to develop your software the credential file name must be added to the *.gitignore* file. By doing this you will keep your credentials in a safer way. Keep in mind that this kind of workflow doesn't stop our credentials to be compromised if we get hacked.
    In resume, this is a better way to work but not the safest at all.

* Asking for the credentials in every execution: 
    This is a really safe way to manage credentials. With the *getpass* python library we can get the credentials and save them into variables.
    As you can guess this practice is as secure as inefficient. We would have to input the user and password every time which could be very tedious and unproductive.

    ```python
    import getpass
    # If you want to hide the username also
    user = getpass.getpass('Username: ') 

    password = getpass.getpass('Password: ')

    # Using your credentials...
    ```

* Storing creds as enviroment variables.
    Another way to manage credentials is to store them but as enviroment variables.
    Depending on the OS used we will have to work with one of the following methods:
    * On Linux: Add to the *~/.bashrc* file the line:
        ```bash
        export API_PASSWORD="supersecretpass"
        ```
    * On Windows: Follow this [link][windows_env_var]
    
    In order to store the password into a variable we only have to run:
    ```python
    import os
    password = os.getenv('API_PASSWORD')
    ```
    The drawback of this method is that we will mess up your OS enviroment with variables that you are going to use only in a specifyc application/software.
     
* Storing credentials in **.env** file:
    This method is similar to *Storing credentiales in plain text files*. We need to create an **.env** file with the creds:
    ```bash
    echo "API_PASSWORD=super_secret_password" > environment.env
    ```
    To recover the password:
    ```python
    import dotenv
    import os

    dotenv.load_dotenv('environment.env')
    api_key = os.getenv('API_PASSWORD')
    # Use your api password...
    ```
    This solves the problematic of messing up your OS enviroment, but it still isn't the cleanest way.

* Using Keyring: 
    There is a Python library called *Keyring* that allows to store credentials under the home directory. These variables will also be encrypted with the current user's password. Depending on the OS, keyring will use specifyc system's keyring software.<br>
    
    *If we want to store our api user and password:*
    ```python
    import keyring
    keyring.set_password('MY_API_NAME', 'user', 'super_secret_user')
    keyring.set_password('MY_API_NAME', 'password','super_secret_password')
    ```
    To recover the credentials:
    ```python
    user = keyring.get_credential('MY_API_NAME', 'user')
    password = keyring.get_credential('MY_API_NAME', 'password')
    ```

## Ideal practices

Notice that in the 'good practices' section we covered different ways to store credentials out of the code, but either there weren't encrypted or the encryption relied on the current user's password. This causes a problematic. **One point of failure**.<br>
If someone can get our user and password he will also get our API credentials. If we need to ensure that our API data is protected even if we got hacked we must encrypt our credentials using a key that hasn't been used before.

* Hashing credentials: 
    Hashing is a simple way to secure the credentials.
    Keep in mind that we can't hash-back the credentials so we will have to generate a hashed credentials file and then ask for them every execution, hashing them and compare to the file's ones.
    ```python
    from passlib.hash import bcrypt
    from getpass import getpass

    def generate_creds():
        plain_text = getpass.getpass('Plain text: ')
        hasher = bcrypt.using(rounds=15)
        hashed_text = hasher.hash(plaintext)
        # Write the hashed text in a file...

    def read_creds():
        hashed_text = readfile() # Store the previously hashed creds in a variable
        plain_text = getpass.getpass('Plain text: ')
        hasher = bcrypt.using(rounds=15)
        return hasher.verify(plain_text, hashed_text)
    ```
    This has the same problem we faced before at *Ask for the credentials every execution*, this will make the workflow slower.

* Symmetrical encryption:
    In my opinion, symmetrical encryption is a really powerful way to secure the password and doesn't waste a single bit of productivity (like in *hashing credentials*).
    The drawback of this method is that is by far the most complex to implement and the one who requires the most crypto-algorithm-knowledge.
    We will be using AES-256 CBC, a very well known symmetrical algorithm.

    I could be talking about this algorithm for hours but I am going to jump right to the python implementation and in later posts we will be covering this algorithm thoroughly. <br>

    Notice that in order to use custom length-key we have to derive it to 16-bit length.<br>

    The common import section that we are going to use is:
    ```python
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad,unpad
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA512
    from Crypto.Random import get_random_bytes
    ```

    Function key derivation:
    ```python
    def derive_keys(key):
        salt = b'0'*16
        keys = PBKDF2(key, salt, 64, count=1000000, hmac_hash_module=SHA512)
        key1 = keys[:32]
        print(AES.block_size)
        return key1
    ```

    Encryption:
    ```python
    def encrypt(plaintext, key):
        derived_key = derive_keys(key)
        cipher = AES.new(derived_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        with open('filename', 'wb') as c_file:
            c_file.write(cipher.iv)
            c_file.write(ciphertext)
    ```
    In order to decrypt the data we must store the ciphertext and the initialization vector (iv). A good practice is to store them in separate files but in our example we stored them in the same file.

    Decryption:
    ```python
    def decrypt(ciphertext, key, iv):
        with open(filename, 'rb') as c_file:
            iv = c_file.read(16)
            ciphertext = c_file.read(16)

        derived_key = derive_keys(key)
        cipher_de = AES.new(derived_key, AES.MODE_CBC, iv)
        plain_text = unpad(cipher_de.decrypt(ciphertext), AES.block_size)
        return plain_text
    ```

## Final thoughts

Depending on the relevance of the data we want to protect we are going to use the suited method to store our API credentials. If our data is not very sensitive we can *store credentials on a text file* or use *keyring*. Those two methods are of extreme productivity and very easy to implement. On the other hand if our data is extremely sensitive we must hash/encrypt our API credentials. The method you need relies on your knowledge and responsibility.

Thanks all for reading!


[windows_env_var]: https://docs.oracle.com/en/database/oracle/machine-learning/oml4r/1.5.1/oread/creating-and-modifying-environment-variables-on-windows.html#GUID-DD6F9982-60D5-48F6-8270-A27EC53807D0