smbclient -N -L //<IPADDR>		-N null session(anonymous access) -L ls server shares.  
rpcclient -U “” <IPADDR>		-rpcclient connect to the SMB server ability to send various requests to the SMB server such as srvinfo, enumdomains, querydominfo.  
nmap <IPADDR> -sC -sV -p139,445		-p139 and 445 are used by SMB.  
smbmap -H <IPADDR>		-enumerate SMB server.  

# What version of the SMB server is running on the target system? Submit the entire banner as the answer.  
sudo nmap 10.129.202.5 -sV -sC -p139,445.  

# What is the name of the accessible share on the target?  
smbmap -H 10.129.202.5.  

# Connect to the discovered share and find the flag.txt file. Submit the contents as the answer.
smbclient \\10.129.202.5/sambashare
ls
cd contents
more flag.txt

# Find out which domain the server belongs to.
Downloaded a tool from github enum4linux-ng, provides a lot of information about an SMB server
./enum4linux-ng.py 10.129.202.5 -A

# Find additional information about the specific share we found previously and submit the customized version of that specific share as the answer.
smbmap -H 10.129.202.5
or
./enum4linux-ng.py 10.129.202.5 -A

# What is the full system path of that specific share? (format: "/directory/names")
rpcclient -U “” 10.129.202.5
netshareenumall
