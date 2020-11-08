#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
# Version: 0.0.5
# Updated: 11/7/2020
# ChangeLog:
#
# Sources:
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
#c.execute("INSERT INTO 'group' (id, name) VALUES (1, 'default')")
cur.execute("INSERT INTO 'group' (id, name, enabled, date_added, date_modified, description) VALUES (2, 'Children_BAD', 1, " + UnixEpoch + "," + UnixEpoch + ", 'Very restrictive added by cgray automation')")
cur.execute("INSERT INTO 'group' (id, name) VALUES (3, 'Children_Good')")
cur.execute("INSERT INTO 'group' (id, name) VALUES (4, 'Adults')")

#--- Add three clients ---
cur.execute("INSERT INTO client (id, ip) VALUES (1, '192.168.0.101')")
cur.execute("INSERT INTO client (id, ip) VALUES (2, '192.168.0.102')")
cur.execute("INSERT INTO client (id, ip) VALUES (3, '192.168.0.103')")

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
