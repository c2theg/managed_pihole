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


Version:  0.5.0                             \r\n
Last Updated:  11/8/2020

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
	
	if [ -s "/root/update_pihole_lists.sh" ]
	then
		echo " Deleting files... "
		#------ under crontab -----
		rm /root/pihole_allowlist.sh*
		rm /root/pihole_blocklist.sh*
		rm /root/update_pihole_lists.sh*
		rm /root/pihole_exclude_list.txt*
	fi
	#rm resolv_base.conf*
	#rm pihole_exclude_list.txt
	#rm update_pihole_lists.sh
	#rm update_blocklists_local_servers.sh
	#rm blocklist_regexs_cg.txt
	#rm *.1
	
	echo "Downloading latest versions... \r\n\r\n"
	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/raspi/update_pihole_lists.sh
	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/raspi/pihole_allowlist.sh
	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/raspi/pihole_exclude_list.txt
	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/raspi/blocklist_regexs_cg.txt



	#-- OS base config --
#	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/update_blocklists_local_servers.sh && chmod u+x update_blocklists_local_servers.sh
	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/configs/resolv_base.conf
	cp resolv_base.conf /etc/resolv.conf
	cp resolv_base.conf /etc/resolvconf/resolv.conf.d/base
	
	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/update_time.sh && chmod +u update_time.sh && cp /root/update_time.sh
	#--------------------------------------------------------------------------------------------------------
	wait
    chmod u+x update_lists.sh && chown pihole:www-data update_lists.sh

	chmod u+x pihole_allowlist.sh && chown pihole:www-data pihole_allowlist.sh
	chmod u+x pihole_blocklist.sh && chown pihole:www-data pihole_blocklist.sh	
#	chmod u+x update_pihole_lists-porn.sh && chown pihole:www-data update_pihole_lists-porn.sh
	wait
	
    mv update_lists.sh /root/update_pihole_lists.sh

	mv pihole_exclude_list.txt /root/pihole_exclude_list.txt
#	mv pihole_allowlist.sh /root/pihole_allowlist.sh
#	mv pihole_blocklist.sh /root/pihole_blocklist.sh
	mv blocklist_regexs_cg.txt /etc/pihole/regex.list
	wait
	
	#----------------------------------------------------------------
	echo "Setting up exclude list domains... \r\n "
	
	#---- Update exclude Top Domain, list. to Ignore popular sites, in a effort to expose sites that shouldn't be loaded
	API_EXCLUDE_DOMAINS_list=$(paste -s -d ',' /root/pihole_exclude_list.txt)
	sed -i '/API_EXCLUDE_DOMAINS=/c\'API_EXCLUDE_DOMAINS="$API_EXCLUDE_DOMAINS_list" /etc/pihole/setupVars.conf
	#----------------------------------------------------------------
	#sed -i '/MAXDBDAYS=/c\'MAXDBDAYS="60" /etc/pihole/setupVars.conf
    echo "MAXDBDAYS=90" >> /etc/pihole/setupVars.conf
    echo "IGNORE_LOCALHOST=yes" >> /etc/pihole/setupVars.conf
    echo "RESOLVE_IPV6=yes" >> /etc/pihole/setupVars.conf
    echo "RESOLVE_IPV4=yes" >> /etc/pihole/setupVars.conf
    echo "NAMES_FROM_NETDB=true" >> /etc/pihole/setupVars.conf
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
	sh /root/pihole_blocklist.sh
	wait

	wait
	sh /root/update_time.sh	
else
	echo "
	
	Not connected to the Internet. Fix that first and try again 
	
	"
fi
#-----------------------------------------------------------------------------------------
Cron_output=$(crontab -l | grep "update_pihole_lists.sh")
#echo "The output is: [ $Cron_output ]"
if [ -z "$Cron_output" ]
then
    echo "update_pihole_lists.sh not in crontab. Adding."

    # run “At 04:20.” everyday
    line="20 4 * * * /root/update_pihole_lists.sh >> /var/log/update_pihole_lists.log 2>&1"
    (crontab -u root -l; echo "$line" ) | crontab -u root -

    wait
    /etc/init.d/cron restart  > /dev/null
else
    echo "update_pihole_lists.sh was found in crontab. skipping addition"
fi

echo "Done! \r\n \r\n"
echo "If you want to update and block porn too, please run the following: ./update_pihole_lists-porn.sh \r\n \r\n"