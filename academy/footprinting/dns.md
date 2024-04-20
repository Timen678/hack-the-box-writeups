tools  
man dnsenum  
man dig  

# Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain.  
FQDN stands for fully qualified domain name.  
dig ns inlanefreight.htb @$target

# Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...))  
dig axfr inlanefreight.htb @$target  

# What is the IPv4 address of the hostname DC1?  
dig axfr inlanefreight.htb @$target  

# What is the FQDN of the host where the last octet ends with "x.x.x.203"?  
Downloaded wordlists to enumerate over dns hostnames  
dig axfr inlanefreight.htb @$target  
dnsenum –dnsserver $target –enum -p 0 -s 0 -f /dnsenum-wordlists/fierce-hostlist.txt dev.inlanefreight.htb  
