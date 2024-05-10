## Hbox writeups
Answers are left out for obvious reasons <br>

## Kali Linux time-savings and best practice to make Mati Aharoni and Devon Kearns proud  
Use tmux to manage multiple terminal instances <br>
tmux		- start  

Ctrl+b %	- split window into two horizontal panes
Ctrl+b “	- split window into two vertical panes
Ctrl+b ←, →, ↑, ↓	- move to pane
Ctrl+b x	- delete current pane

Ctrl+b C	- create window
tmux ls		- ls
Ctrl+b 0, 1, 2, etc	- switch to the window with that index
Ctrl+b n 	- move to the next window
Ctrl+b p	- move to the previous window
Ctrl+b w 	- list all windows and select one from the list
Ctrl+b &	- delete current window

Store your target IP address and information that you'll frequently use into variables
export <var_name>=<store>
To access the stored data
$var_name
echo $var_name

xclip, clipboard tool for various uses such as copying output of a command or grep  
sudo apt install xclip  
<command> | xclip -selection clipboard  
<command> | grep <word> | -selection clipboard  
