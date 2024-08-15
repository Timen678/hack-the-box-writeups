# Kali Linux time-savings and best practices to make Mati Aharoni and Devon Kearns proud  
Use tmux to manage multiple terminal instances <br>
sudo apt install tmux <br>
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
Ctrl+b :  - tmux command prompt <br>
Ctrl+b : + resize-pane -L,-R,-U,-D X  - resize current pane by X amount in direction left(L), right(R), up(U), or down(D) <br>
ctrl+b z  - zoom in/out on current pane, useful for mouse selection to copy text <br>
ctrl+b [  - enable arrow key scrolling | press q to exit mode <br>
<br>
Store your target IP address and information that you'll frequently use into variables <br>
export <var_name>=<store>  - store value in var_name <br>
$var_name  - access value stored in var_name. E.g. ping $var_name <br>
<br>
xclip, clipboard tool for various uses such as copying output of a command or grep <br>
sudo apt install xclip <br>
<command> | xclip -selection clipboard <br>
<command> | grep <word> | -selection clipboard <br>
