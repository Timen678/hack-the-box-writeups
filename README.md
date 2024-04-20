## Kali Linux time-savings and best practice to make Mati Aharoni proud  

Store your target IP address and information that you'll frequently use into variables.  
export <var_name>=<store>
To access the stored data  
$var_name
echo $var_name

xclip, clipboard tool for various uses such as copying output of a command or grep  
sudo apt install xclip  
<command> | xclip -selection clipboard  
<command> | grep <word> | -selection clipboard  
