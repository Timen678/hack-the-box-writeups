smtp port 25  
man nmap  
e.gs.  
sudo nmap 10.129.14.128 -sC -sV -p25  
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v  

# Enumerate the SMTP service and submit the banner, including its version as the answer.  
telnet $target 25  

# Enumerate the SMTP service even further and find the username that exists on the system  
smtp-user-enum -U footprinting-wordlist.txt -t $target  
initially tried with default wait time(5s) however that was too quick of a timeout for the server to respond. Upped it to -w 20, worked.  
smtp-user-enum -w 20 -U footprinting-wordlist.txt -t $target  

PS footprinting-wordlist is provided in the module  
