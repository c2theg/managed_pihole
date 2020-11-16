#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
# Version: 0.0.14
# Updated: 11/16/2020
# ChangeLog:
#
# Sources:
#     https://pi-hole.net/2020/05/10/pi-hole-v5-0-is-here/#page-content
#     https://docs.pi-hole.net/database/
#     https://docs.pi-hole.net/database/gravity/example/
#     
#
#---- Standard Libs ----------------------------------------------
import sys, socket, signal, os, pprint
from datetime import datetime, date, time, timezone, timedelta, tzinfo
import sqlite3

#-----------------------------------------------------------------
pp = pprint.PrettyPrinter(indent=4)
#-----------------------------------------------------------------
now = datetime.now(timezone.utc) - timedelta(days=0) # UTC TIME!!!!!
#NowHuman = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")  # CURRENT TIME NOW!
UnixEpoch = now.strftime("%s")

# Query DB:  /etc/pihole/pihole-FTL.db
# Domain DB: /etc/pihole/gravity.db

FilePath_pihole = "/etc/pihole/"
File_PiHole = "gravity.db"
Adlist_File = "cgray_blocklists.txt"

#--- Backup Databse --- probably shouldnt do this everytime
#./backup_dbs.py

os.system("pihole -v -c")
os.system("pihole status")
#--- Backup Databse --- probably shouldnt do this everytime
#./backup_dbs.py
os.system("pihole -a fahrenheit")
os.system("pihole -a email admin@domain.com")

print ("Updating pihole-FTL... \r\n \r\n")
os.system("pihole -up")
#----------------------
#print ("stopping pihole-FTL... \r\n \r\n")
#os.system("pihole-FTL stop")

#--- Connect ---
conn = None
try:
    conn = sqlite3.connect(FilePath_pihole + File_PiHole)
    cur = conn.cursor()
    print ("Connected to sqlite3 db: " + FilePath_pihole + File_PiHole + " \r\n \r\n")
except Error as e:
    print(e)
    quit

#---------------------------------------------------------------------------
#--- Add groups ---
#c.execute("INSERT OR IGNORE INTO 'group' (id, name) VALUES (1, 'default')")
cur.execute("INSERT OR IGNORE INTO 'group' (id, name, enabled, date_added, date_modified, description) VALUES (2, 'Children', 1, " + UnixEpoch + "," + UnixEpoch + ", 'Blocks: porn, ads, fake news')")
cur.execute("INSERT OR IGNORE INTO 'group' (id, name, enabled, date_added, date_modified, description) VALUES (3, 'Children_Fun', 1, " + UnixEpoch + "," + UnixEpoch + ", 'Blocks: Games, Chat, Streaming Video & Audio')")

#cur.execute("INSERT OR IGNORE INTO 'group' (id, name, enabled, date_added, date_modified, description) VALUES (4, 'Children_Good', 1, " + UnixEpoch + "," + UnixEpoch + ", 'Blocks malware,ads and porn')")
#cur.execute("INSERT OR IGNORE INTO 'group' (id, name, enabled, date_added, date_modified, description) VALUES (5, 'Children_Education', 1, " + UnixEpoch + "," + UnixEpoch + ", 'For Remote Learning, Allows: Youtube / Google Classroom, Zoom')")
#cur.execute("INSERT OR IGNORE INTO 'group' (id, name, enabled, date_added, date_modified, description) VALUES (6, 'Children_Bed', 1, " + UnixEpoch + "," + UnixEpoch + ", 'Blocks: almost everything, so they go to sleep')")
#cur.execute("INSERT OR IGNORE INTO 'group' (id, name, enabled, date_added, date_modified, description) VALUES (7, 'Adults', 1, " + UnixEpoch + "," + UnixEpoch + ", 'Blocks: porn, mature content')")


#--- Add three clients ---
cur.execute("INSERT OR IGNORE INTO 'client' (ip, date_added, date_modified, comment) VALUES ('192.168.0.101'," + UnixEpoch + "," + UnixEpoch + ", '<Person_Name> - <Device> (Public MAC) - <usecase> - <conn type>')")
#cur.execute("INSERT OR IGNORE INTO 'client' (ip, date_added, date_modified, comment) VALUES ('192.168.0.102'," + UnixEpoch + "," + UnixEpoch + ", 'Son - iPad')")
cur.execute("INSERT OR IGNORE INTO 'client' (ip, date_added, date_modified, comment) VALUES ('192.168.0.103'," + UnixEpoch + "," + UnixEpoch + ", 'Son - iPad (Public Addr')")
cur.execute("INSERT OR IGNORE INTO 'client' (ip, date_added, date_modified, comment) VALUES ('192.168.0.104'," + UnixEpoch + "," + UnixEpoch + ", 'Son - Laptop - school - wifi')")

#cur.execute("INSERT OR IGNORE INTO 'client' (ip, date_added, date_modified, comment) VALUES ('192.168.0.105'," + UnixEpoch + "," + UnixEpoch + ", 'Daughter - iPhone')")
#cur.execute("INSERT OR IGNORE INTO 'client' (ip, date_added, date_modified, comment) VALUES ('192.168.0.106'," + UnixEpoch + "," + UnixEpoch + ", 'Daughter - Laptop - school - wifi')")
cur.execute("INSERT OR IGNORE INTO 'client' (ip, date_added, date_modified, comment) VALUES ('192.168.0.107'," + UnixEpoch + "," + UnixEpoch + ", 'Daughter - Laptop - home - wifi')")

# cur.execute("INSERT INTO 'client' (id, ip, date_added, date_modified, comment) VALUES (8, '192.168.0.108'," + UnixEpoch + "," + UnixEpoch + ", 'Mom - iPhone')")
# cur.execute("INSERT INTO 'client' (id, ip, date_added, date_modified, comment) VALUES (9, '192.168.0.109'," + UnixEpoch + "," + UnixEpoch + ", 'Mom - Laptop - home - wifi')")

# cur.execute("INSERT INTO 'client' (id, ip, date_added, date_modified, comment) VALUES (10, '192.168.0.109'," + UnixEpoch + "," + UnixEpoch + ", 'Dad - Laptop - work - wifi')")
# cur.execute("INSERT INTO 'client' (id, ip, date_added, date_modified, comment) VALUES (11, '192.168.0.110'," + UnixEpoch + "," + UnixEpoch + ", 'Dad - Laptop - work - eth0')")
# cur.execute("INSERT INTO 'client' (id, ip, date_added, date_modified, comment) VALUES (12, '192.168.0.111'," + UnixEpoch + "," + UnixEpoch + ", 'Dad - Laptop - home - wifi')")
# cur.execute("INSERT INTO 'client' (id, ip, date_added, date_modified, comment) VALUES (13, '192.168.0.112'," + UnixEpoch + "," + UnixEpoch + ", 'Dad - Android - work - wifi')")
# cur.execute("INSERT INTO 'client' (id, ip, date_added, date_modified, comment) VALUES (14, '192.168.0.113'," + UnixEpoch + "," + UnixEpoch + ", 'Dad - Android - home - wifi')")


#-------------- Add clients to groups -----------------------
#--- Son ---
cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (1, 1)")
cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (2, 1)")
cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (3, 1)")

cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (2, 2)")
cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (3, 2)")
#--- Daugther ---
cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (4, 1)")
cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (4, 2)")

#--- Mom ---
# cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (8, 7)")
# cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (9, 7)")

# #--- Dad ---
# cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (12, 7)")
# cur.execute("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (14, 7)")

#---------------------------------------------------------------------------
#------------ DONE ------------------
print("Commiting changes to db... ")
conn.commit()
print ("Saved! \r\n \r\n \r\n")
# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
print ("\r\n \r\n Closing sqlite connection. \r\n")
conn.close()

#print ("Starting pihole FTL (Faster then light) DNS Sever... \r\n")
#os.system("start pihole-FTL")

#print ("Updating DNS lists... \r\n")
#os.system("pihole restartdns reload-lists")

#print ("Updating gravity domains... \r\n")
#os.system("pihole -g")

#------------------------------------------------
print ("DONE! ")
