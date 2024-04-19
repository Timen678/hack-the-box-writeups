sudo nmap -sV -p21 -sC -A <IPADDR>	nmap scan on port 21, -sV version scan, -sC default script scan, -A aggressive scan provides more information but way more likely to be detected. 
–script ftp-anon check if the FTP server allow anonymous access, ftp-syst display status of the FTP server, including configs etc. –script-trace is used to display what commands the script send.
ways to connect to FTP:
nc -nv 10.129.14.136 21
telnet 10.129.14.136 21
openssl s_client -connect 10.129.14.136:21 -starttls ftp

# Which version of the FTP server is running on the target system? Submit the entire banner as the answer.
nmap --script ftp-anon 10.129.43.135	-checks if the ftp server allow anonymous access, i.e login with user anonymous and w/e password.
The ftp server does allow anon access
ftp anonymous@10.129.43.135
password w/e
success
ls
more flag.txt
