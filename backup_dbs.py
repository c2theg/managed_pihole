#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------
#  * Copyright (c) 2021 Christopher Gray
#  * All rights reserved.  Proprietary and Confidential.
# Version: 0.0.1
# Updated: 11/7/2020
# ChangeLog:
#     Initial release for James
#
#
# Sources:
#     https://docs.pi-hole.net/database/
#
#
#---- Standard Libs ----------------------------------------------
import sys, socket, signal, os
import sqlite3, gzip
#----- Timeout Boilerplate ---------------------------------------
def set_run_timeout(timeout):
    # Set maximum execution time of the current Python process
    def alarm(*_):
        raise SystemExit("Timed out!")
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(timeout)
set_run_timeout(600) # Set maximum execution time, in seconds
#-----------------------------------------------------------------

# Query DB:  /etc/pihole/pihole-FTL.db
# Domain DB: /etc/pihole/gravity.db

#----- Work -----
FilePath_pihole = "/etc/pihole/"
FilePath_backuploc = "/home/pi/"
FilesList = ["pihole-FTL.db", "gravity.db"]

for i in FilesList:
    print("Backing up database ", i, " (To location: ", FilePath_backuploc, ") ...  ")
    #sqlite3 /etc/pihole/pihole-FTL.db ".backup /home/pi/pihole-FTL.db.backup"
    sqlite3 FilePath_pihole + i + ".backup " + FilePath_backuploc + i + ".backup"

    print("Compressing db... ")
    with open(FilePath_backuploc + i + ".backup", 'rb') as f_in:
        with gzip.open(FilePath_backuploc + i + ".backup.gz", 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    print("Done! \r\n")

print("All backups have been completed! \r\n \r\n")