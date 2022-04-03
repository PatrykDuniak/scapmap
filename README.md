# scapmap
 _____                                       
/  ___|                                      
\ `--.  ___ __ _ _ __  _ __ ___   __ _ _ __  
 `--. \/ __/ _` | '_ \| '_ ` _ \ / _` | '_ \ 
/\__/ / (_| (_| | |_) | | | | | | (_| | |_) |
\____/ \___\__,_| .__/|_| |_| |_|\__,_| .__/ 
                | |                   | |    
                |_|                   |_|    

Welcome to Scapmap! Port scanner written in python based on scapy library.
Purpose:
Just to learn how scanning ports works and have good understanding how TCP works on packet level. And have a scanner that works fine on Windows too. But I'm not sure that everything works correctly on theoretical and programming level.

Prerequisites:
>OS: Works fine on Windows, MacOS and Linux distributions (tested only on debian like and manjaro)
>Python version: Tested on Python 3.9.7 but should work on others too
>Scapy version: Tested on 2.4.5, older versions can have some problems

Examples of use:
This application allows you to use different scans and discovery in 1 command on 1 host or multiple of them.
If you see a lot of 'Protocol open OR filtered' that means that whole traffic was cutted by a target or just host is down (but that depends of type of scan etc. - nmap documentation explains it well), check it with discovery functions like ARPing.

Ping whole subnet, in -ICMPing we are providing
>python scapmap.py -ip 192.168.0.1/24 -ICMPing
We can also specific icmp code like 13 te get timestamps
>python scapmap.py -ip 192.168.0.1/24 -ICMPing 13

Scan ports with TCP SYN, FIN, Xmas on range 80-139
>python scapmap.py -ip 192.168.1.254 -p 80-139 -SYN -FIN -Xmas
There is a chance to see a lot of 'Filtered' even if host is not filtering traffic, we can change timeout time and set specific_result flag to see less and more proper results (but if host is not filtering traffic only in SYN we can see less results, cause 'port  closed' in my opinion is specific result).
>python scapmap.py -ip 192.168.1.254 -p 80-139 -SYN -FIN -Xmas --timeout 1 --specific_result

We can also combine host discovery and port scans
>python scapmap.py -ip 192.168.1.254/30 -p 80 -ARPing -SYN -UDP -IProt -Custom 'F S R' --timeout 0.01 --specific_result