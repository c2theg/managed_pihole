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


Version:  0.5.3                             \r\n
Last Updated:  11/12/2020

location: 

"
wait

#-----------------------------------------------------------------------------------------
Cron_output=$(crontab -l | grep "update_lists.sh")
#echo "The output is: [ $Cron_output ]"
if [ -z "$Cron_output" ]
then
    echo "update_lists.sh not in crontab. Adding."

    # run “At 04:20.” everyday
    line="20 4 * * * /root/update_lists.sh > /var/log/update_lists.log 2>&1"
    (crontab -u root -l; echo "$line" ) | crontab -u root -

    wait
    /etc/init.d/cron restart  > /dev/null
else
    echo "update_lists.sh was found in crontab. skipping addition"
fi

#--------------------------------------------------------------------------------------------
echo "Checking Internet status...\r\n\r\n"
ping -q -c3 github.com > /dev/null
if [ $? -eq 0 ]
then
	echo "Connected!!!"
	#-- OS base config --
#	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/update_blocklists_local_servers.sh && chmod u+x update_blocklists_local_servers.sh
	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/configs/resolv_base.conf
	cp resolv_base.conf /etc/resolv.conf
	cp resolv_base.conf /etc/resolvconf/resolv.conf.d/base	
	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/update_time.sh && chmod u+x update_time.sh
	#--------------------------------------------------------------------------------------------------------
    #echo "Add repo keys... "
    #apt-key adv --keyserver   keyserver.ubuntu.com --recv-keys 7638D0442B90D010
    #apt-key adv --keyserver   keyserver.ubuntu.com --recv-keys 04EE7237B7D453EC
	#----------------------------------------------------------------
	#sed -i '/MAXDBDAYS=/c\'MAXDBDAYS="60" /etc/pihole/setupVars.conf
    echo "MAXDBDAYS=90" >> /etc/pihole/setupVars.conf
    echo "IGNORE_LOCALHOST=yes" >> /etc/pihole/setupVars.conf
    echo "RESOLVE_IPV6=yes" >> /etc/pihole/setupVars.conf
    echo "RESOLVE_IPV4=yes" >> /etc/pihole/setupVars.conf
    echo "NAMES_FROM_NETDB=true" >> /etc/pihole/setupVars.conf
    echo "DNS_FQDN_REQUIRED=true" >> /etc/pihole/setupVars.conf
    echo "DNS_BOGUS_PRIV=true" >> /etc/pihole/setupVars.conf

    #echo "PIHOLE_DNS_1=127.0.0.1#5053" >> /etc/pihole/setupVars.conf  # CLOUDFLARED DOH

    sed -i '/PIHOLE_DNS_1=/c\'PIHOLE_DNS_1=1.1.1.2 /etc/pihole/setupVars.conf
    sed -i '/PIHOLE_DNS_2=/c\'PIHOLE_DNS_2=9.9.9.9 /etc/pihole/setupVars.conf
    echo "PIHOLE_DNS_3=208.67.222.222" >> /etc/pihole/setupVars.conf
    echo "PIHOLE_DNS_4=2606:4700:4700::1111" >> /etc/pihole/setupVars.conf
    echo "PIHOLE_DNS_5=8.8.8.8" >> /etc/pihole/setupVars.conf
    echo "PIHOLE_DNS_6=2620:119:53::53" >> /etc/pihole/setupVars.conf
    #-------------------------------------------------------------------------
    wait
    chmod u+x initial_setup.py
    sudo ./initial_setup.py

    wait
	sh ./update_time.sh
fi


echo "Done! \r\n \r\n"