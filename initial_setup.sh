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


Version:  0.5.1                             \r\n
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
    line="20 4 * * * /root/update_lists.sh >> /var/log/update_lists.log 2>&1"
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
	sudo wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/update_time.sh && chmod +u update_time.sh
	#--------------------------------------------------------------------------------------------------------
    #echo "Add repo keys... "
    #apt-key adv --keyserver   keyserver.ubuntu.com --recv-keys 7638D0442B90D010
    #apt-key adv --keyserver   keyserver.ubuntu.com --recv-keys 04EE7237B7D453EC

    wait
    chmod u+x initial_setup.py
    sudo ./initial_setup.py

    wait
	sh /root/update_time.sh
fi


echo "Done! \r\n \r\n"