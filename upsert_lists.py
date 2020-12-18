#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
Version = "0.0.41"
Updated = "12/18/2020"
# ChangeLog:
#
# Sources:
#     https://docs.pi-hole.net/database/
#     https://docs.pi-hole.net/database/gravity/example/
#     
#
print ("Version: ", Version)
print ("Updated: ", Updated)

#---- Standard Libs ----------------------------------------------
import sys, socket, signal, os, pprint
from datetime import datetime, date, time, timezone, timedelta, tzinfo
import sqlite3

#-----------------------------------------------------------------
pp = pprint.PrettyPrinter(indent=4)
#-----------------------------------------------------------------
# Query DB:  /etc/pihole/pihole-FTL.db
# Domain DB: /etc/pihole/gravity.db

FilePath_pihole = "/etc/pihole/"
File_PiHole = "gravity.db"
Adlist_File = "cgray_blocklists.txt"

#----  Cleanup ----
os.system("sudo rm /var/log/pihole-FTL.log.*")
os.system("sudo rm /var/log/pihole.log.*")

os.system("pihole -v -c")
os.system("pihole status")

print ("Cleaning up pihole Db... \r\n \r\n")
os.system("pihole flush")

print ("stopping pihole-FTL... \r\n \r\n")
os.system("pihole -up")
#----------------------
print ("stopping pihole-FTL... \r\n \r\n")
os.system("sudo service pihole-FTL stop")

#--- Connect ---
conn = None
try:
    conn = sqlite3.connect(FilePath_pihole + File_PiHole)
    cur = conn.cursor()
    print ("Connected to sqlite3 db: " + FilePath_pihole + File_PiHole + " \r\n \r\n")
except Error as e:
    print(e)
    quit


dbCommit = False
RowsToAdd = []
count = 0
now = datetime.now(timezone.utc) - timedelta(days=0) # UTC TIME!!!!!
#NowHuman = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")  # CURRENT TIME NOW!
UnixEpoch = now.strftime("%s")

with open(Adlist_File, 'r') as fp: 
    for line in fp: 
        count += 1
        lineContent = line.strip()
        if not lineContent or line[0] == "#": # if line is empty, move to next line
            #print ("Skipping line: " + str(count) + "\r\n")
            continue
        #print("Line{}: {} \r\n".format(count, lineContent)) 
        #print ("Searching for: [" + str(lineContent) + "] \r\n")
        # Query db to see if entry exists
        cur.execute("SELECT id FROM adlist WHERE address=?", (lineContent,))
        rows = cur.fetchone()
        if rows != None:
            #print(rows, "\r\n")
            for row in rows:
                print(" *** Exists in db: " + str(row) + ",  URL: " + str(lineContent) + " *** \r\n")
        else:
            dbCommit = True
            print ('Adding entry to pending list: ', str(lineContent), ' \r\n')
            #c.execute("INSERT INTO 'adlist' (address, enabled,date_added, date_modified,comment) VALUES (", str(lineContent), ",  '1', " + strftime("%s","now") + ", " + strftime("%s","now") + ", '+cgray importer'");  # add entry to db
            AddEntry = (str(lineContent), '1', UnixEpoch, UnixEpoch, 'cg importer')
            RowsToAdd.append(AddEntry)


#------------ blocklist_regexs --------------------
Adlist_File = "blocklist_regexs_cg.txt"
RegexEntries = []
with open(Adlist_File, 'r') as fp: 
    for line in fp:
        count += 1
        lineContent = line.strip()
        if not lineContent or line[0] == "#": # if line is empty, move to next line
            #print ("Skipping line: " + str(count) + "\r\n")
            continue
        #print("Line{}: {} \r\n".format(count, lineContent)) 
        #print ("Searching for: [" + str(lineContent) + "] \r\n")
        # Query db to see if entry exists
        cur.execute("SELECT id FROM domainlist WHERE domain=?", (lineContent,))
        rows = cur.fetchone()
        if rows != None:
            #print(rows, "\r\n")
            for row in rows:
                print(" *** Exists in db: " + str(row) + ",  URL: " + str(lineContent) + " *** \r\n")
        else:
            dbCommit = True
            print ('Adding entry to pending list: ', str(lineContent), ' \r\n')
            #c.execute("INSERT INTO 'adlist' (address, enabled,date_added, date_modified,comment) VALUES (", str(lineContent), ",  '1', " + strftime("%s","now") + ", " + strftime("%s","now") + ", '+cgray importer'");  # add entry to db
            AddEntry = (str(lineContent), '3','1', UnixEpoch, UnixEpoch, 'cg importer')
            RegexEntries.append(AddEntry)


#------------ ALLOW_regexs --------------------
Adlist_File = "allowlist_regexs_cg.txt"
RegexEntries = []
with open(Adlist_File, 'r') as fp: 
    for line in fp:
        count += 1
        lineContent = line.strip()
        if not lineContent or line[0] == "#": # if line is empty, move to next line
            #print ("Skipping line: " + str(count) + "\r\n")
            continue
        #print("Line{}: {} \r\n".format(count, lineContent)) 
        #print ("Searching for: [" + str(lineContent) + "] \r\n")
        # Query db to see if entry exists
        cur.execute("SELECT id FROM domainlist WHERE domain=?", (lineContent,))
        rows = cur.fetchone()
        if rows != None:
            #print(rows, "\r\n")
            for row in rows:
                print(" *** Exists in db: " + str(row) + ",  URL: " + str(lineContent) + " *** \r\n")
        else:
            dbCommit = True
            print ('Adding entry to pending list: ', str(lineContent), ' \r\n')
            #c.execute("INSERT INTO 'adlist' (address, enabled,date_added, date_modified,comment) VALUES (", str(lineContent), ",  '1', " + strftime("%s","now") + ", " + strftime("%s","now") + ", '+cgray importer'");  # add entry to db
            AddEntry = (str(lineContent), '0','2', UnixEpoch, UnixEpoch, 'cg importer')
            RegexEntries.append(AddEntry)


#------------ ALLOW_regexs --------------------
Adlist_File = "allow_regex_social_cg.txt"
RegexEntries = []
with open(Adlist_File, 'r') as fp: 
    for line in fp:
        count += 1
        lineContent = line.strip()
        if not lineContent or line[0] == "#": # if line is empty, move to next line
            #print ("Skipping line: " + str(count) + "\r\n")
            continue
        #print("Line{}: {} \r\n".format(count, lineContent)) 
        #print ("Searching for: [" + str(lineContent) + "] \r\n")
        # Query db to see if entry exists
        cur.execute("SELECT id FROM domainlist WHERE domain=?", (lineContent,))
        rows = cur.fetchone()
        if rows != None:
            #print(rows, "\r\n")
            for row in rows:
                print(" *** Exists in db: " + str(row) + ",  URL: " + str(lineContent) + " *** \r\n")
        else:
            dbCommit = True
            print ('Adding entry to pending list: ', str(lineContent), ' \r\n')
            #c.execute("INSERT INTO 'adlist' (address, enabled,date_added, date_modified,comment) VALUES (", str(lineContent), ",  '1', " + strftime("%s","now") + ", " + strftime("%s","now") + ", '+cgray importer'");  # add entry to db
            AddEntry = (str(lineContent), '0','2', UnixEpoch, UnixEpoch, 'cg importer')
            RegexEntries.append(AddEntry)

            
#---------------------------------------------------------------------------------------
if dbCommit == True:
    print("\r\n \r\n ------ About to add the following entries ------ \r\n \r\n")
    pp.pprint(RowsToAdd)
    print("\r\n \r\n")
    cur.executemany('INSERT OR IGNORE INTO adlist(address, enabled,date_added, date_modified, comment) VALUES (?,?,?,?,?)', RowsToAdd)
    
    #---- RegEx's ----------
    pp.pprint(RegexEntries)
    print("\r\n \r\n")
    cur.executemany('INSERT OR IGNORE INTO domainlist(domain, type, enabled, date_added, date_modified, comment) VALUES (?,?,?,?,?,?)', RegexEntries)


    #------------ DONE ------------------
    print("Commiting changes to db... ")
    conn.commit()
    print ("Saved! \r\n \r\n \r\n")
    # We can also close the connection if we are done with it.
    # Just be sure any changes have been committed or they will be lost.
    print ("\r\n \r\n Closing sqlite connection. \r\n")
    conn.close()

else:
    print ("** NOTHING TO Up/sert ***")
    # We can also close the connection if we are done with it.
    # Just be sure any changes have been committed or they will be lost.
    print ("\r\n \r\n Closing sqlite connection. \r\n")
    conn.close()
#------------------------------------------------

print ("Starting pihole FTL (Faster then light) DNS Sever... \r\n")
os.system("sudo service pihole-FTL start")

print ("Updating DNS lists... \r\n")
os.system("pihole restartdns reload-lists")
#stream = os.popen('pihole restartdns reload-lists')
#output = stream.read()
#print (str(output))

print ("Updating gravity domains... \r\n")
os.system("pihole -g")

print ("DONE! ")
