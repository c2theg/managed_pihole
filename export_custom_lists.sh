#!/bin/sh
echo "
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
Version:  0.0.1  
Last Updated:  9/29/2023
location: 
"
wait

pihole-FTL sqlite3  /etc/pihole/gravity.db "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 0;" > exwhite.txt
pihole-FTL sqlite3  /etc/pihole/gravity.db "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 1;" > exblack.txt
pihole-FTL sqlite3  /etc/pihole/gravity.db "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 2;" > regwhite.txt
pihole-FTL sqlite3  /etc/pihole/gravity.db "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 3;" > regblack.txt

echo "Done exporting all files! \r\n \r\n "
