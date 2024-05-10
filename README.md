# Kali Linux time-savings and best practice to make Mati Aharoni and Devon Kearns proud  
Use tmux to manage multiple terminal instances <br>
tmux		- start <br>
Ctrl+b %	- split window into two horizontal panes <br>
Ctrl+b “	- split window into two vertical panes <br>
Ctrl+b ←, →, ↑, ↓	- move to pane <br>
Ctrl+b x	- delete current pane <br>
Ctrl+b C	- create window <br>
tmux ls		- ls <br>
Ctrl+b 0, 1, 2, etc	- switch to the window with that index <br>
Ctrl+b n 	- move to the next window <br>
Ctrl+b p	- move to the previous window <br>
Ctrl+b w 	- list all windows and select one from the list <br>
Ctrl+b &	- delete current window <br>
<br>
Store your target IP address and information that you'll frequently use into variables <br>
export <var_name>=<store> <br>
To access the stored data <br>
$var_name <br>
echo $var_name <br>
<br>
xclip, clipboard tool for various uses such as copying output of a command or grep <br>
sudo apt install xclip <br>
<command> | xclip -selection clipboard <br>
<command> | grep <word> | -selection clipboard <br>
