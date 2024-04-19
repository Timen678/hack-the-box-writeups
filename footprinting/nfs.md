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

# Enumerate the NFS service and submit the contents of the flag.txt in the "nfs" share as the answer.
sudo nmap –script nfs* 10.129.19.209 -sV -p111,2049	to see where the file is located  
sudo mount -t nfs 10.129.19.209:/var/nfs ./target-nfs -o nolock		- mounted the share  
ls ~/target-nfs  
cat flag.txt  

# Enumerate the NFS service and submit the contents of the flag.txt in the "nfsshare" share as the answer.  
sudo nmap –script nfs* 10.129.19.209 -sV -p111,2049    to see where the file is located  
sudo mount -t nfs 10.129.19.209:/mnt/nfsshare ./target-nfs -o nolock   	 - mounted the share  
ls ~/target-nfs  
cat flag.txt  
