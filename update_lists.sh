#!/bin/sh
#
clear
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

now=$(date)
echo "Running update_lists.sh at $now \r\n
Current working dir: $SCRIPTPATH \r\n \r\n
 _____             _         _    _          _                                   
|     |___ ___ ___| |_ ___ _| |  | |_ _ _   |_|                                  
|   --|  _| -_| .'|  _| -_| . |  | . | | |   _                                   
|_____|_| |___|__,|_| |___|___|  |___|_  |  |_|                                  
                                     |___|                                       
                                                                                 
 _____ _       _     _           _              _____    __    _____             
|     | |_ ___|_|___| |_ ___ ___| |_ ___ ___   |     |__|  |  |   __|___ ___ _ _ 
|   --|   |  _| |_ -|  _| . | . |   | -_|  _|  | | | |  |  |  |  |  |  _| .'| | |
|_____|_|_|_| |_|___|_| |___|  _|_|_|___|_|    |_|_|_|_____|  |_____|_| |__,|_  |
                            |_|                                             |___|


Version:  0.5.10
Last Updated:  12/26/2020

location: 

"
wait


#--------------------------------------------------------------------------------------------
echo "Checking Internet status...\r\n\r\n"
ping -q -c3 github.com > /dev/null
if [ $? -eq 0 ]
then
	echo "Connected!!!"

    #echo "Add repo keys... "
    #apt-key adv --keyserver   keyserver.ubuntu.com --recv-keys 7638D0442B90D010
    #apt-key adv --keyserver   keyserver.ubuntu.com --recv-keys 04EE7237B7D453EC

    echo "Downloading required dependencies... "
    #sudo apt update
    sudo apt-get update
    sudo apt dist-upgrade -y
    sudo apt-get autoclean
    sudo apt-get upgrade -y

	if [ -s "/etc/pihole/backup/" ]
	then
		echo "Backing up pihole... "
        mkdir -p /etc/pihole/backup/
		#mkdir -p /etc/pihole/backup/dnsmasq.d/
		#cp /etc/dnsmasq.d/*  /etc/pihole/backup/dnsmasq.d/
		cp /etc/pihole/setupVars.conf /etc/pihole/backup/
		#cp /etc/pihole/adlists.list   /etc/pihole/backup/
		cp /etc/pihole/whitelist.txt  /etc/pihole/backup/
		cp /etc/pihole/blacklist.txt  /etc/pihole/backup/
		#cp /etc/pihole/wildcardblocking.txt /etc/pihole/backup/
	fi
	
	echo " Deleting files... "
	rm update_lists.*
	rm cgray_blocklists.*
	rm pihole_allowlist.*
	rm pihole_exclude_list.*
	rm blocklist_regexs_cg.*
	rm initial_setup.*
	rm backup_dbs.*
	rm upsert_lists.*
	rm update_time.*
	rm resolv_base.conf.*
	rm cgray_regex_blocks.txt.*
	rm allow_regex_social_cg.txt
	rm allowlist_regexs_cg.txt
	rm cleanup.sh.*

	if [ -s "/root/update_lists.sh" ]
	then
		rm /root/update_lists.*
	fi

	echo "Downloading latest versions... \r\n\r\n"
        sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/update_lists.sh
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/cgray_blocklists.txt
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/pihole_allowlist.sh
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/pihole_exclude_list.txt
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/blocklist_regexs_cg.txt

	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/initial_setup.sh
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/initial_setup.py
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/backup_dbs.py
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/upsert_lists.py
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/allow_regex_social_cg.txt
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/allowlist_regexs_cg.txt
	sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/cleanup.sh
	
	#--- set permissions ---
	chmod u+x *.sh
	chmod u+x *.py
	chown pihole:www-data *.sh
	chown pihole:www-data *.py
	#----------------------

	cp update_lists.sh /root/update_lists.sh
	cp upsert_lists.py /root/upsert_lists.py
	wait
	#----------------------------------------------------------------
	echo "Setting up exclude list domains... \r\n "
	#---- Update exclude Top Domain, list. to Ignore popular sites, in a effort to expose sites that shouldn't be loaded
        mv pihole_exclude_list.txt /root/pihole_exclude_list.txt
	API_EXCLUDE_DOMAINS_list=$(paste -s -d ',' /root/pihole_exclude_list.txt)
	sed -i '/API_EXCLUDE_DOMAINS=/c\'API_EXCLUDE_DOMAINS="$API_EXCLUDE_DOMAINS_list" /etc/pihole/setupVars.conf'	
	#----------------------------------------------------------------
	echo "Updating pihole \r\n \r\n"
	sudo pihole -up

	echo "Allow list...
	"
	sleep 2
	sh /root/pihole_allowlist.sh
	wait
	sleep 2
	echo "Black lists... 
	
	"
    wait
    sudo ./upsert_lists.py
else
	echo "
	
	Not connected to the Internet. Fix that first and try again 
	
	"
fi
