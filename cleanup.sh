  
#!/bin/sh
#
clear
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

now=$(date)
echo "Running cleanup.sh at $now \r\n
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
Version:  0.0.1      \r\n
Last Updated:  12/26/2020
location: 
"
wait
#-----------------------------------------------------------------------------------------
echo "Cleaning up pihole Db... \r\n \r\n"


pihole -v -c
pihole status

#----  Cleanup ----
sudo rm /var/log/pihole-FTL.log.*
sudo rm /var/log/pihole.log.*

pihole flush

echo "Stopping pihole-FTL... \r\n "
pihole -up

#----------------------
#echo ("stopping pihole-FTL... \r\n \r\n")
#sudo service pihole-FTL stop


echo "Starting pihole FTL (Faster then light) DNS Sever... \r\n"
sudo service pihole-FTL start
