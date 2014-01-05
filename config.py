# Copyright (c) 2010 Hans Christian v. Stockhausen
# See LICENSE for details.

# Mailreactor configuration settings ------------------------------------------
SMTP_PORT = 25
UID = 1000 # after binding shed root privileges by becoming this user
GID = 1000 # and this group.
HOSTNAME = 'mailreactor.co.za' # mailserver's FQDN
GREYLIST_EXPIRY = 86400 #sec after which a greylist record expires
GREYLIST_CLEANUP_INTERVAL = 3600 #remove expired entries every x seconds
DBHOST = '127.0.0.1'
DBNAME = 'mailreactor'
DBUSER = ''
DBPASS = ''
DBDRIVER= 'psycopg2'
DBCONNECTION_STRING = 'host=%s dbname=%s user=%s password=%s' % (DBHOST,
    DBNAME, DBUSER, DBPASS)
SECRET = '97303e71573c34af06eb0b7dbffc42e2' # used by srs.py to generate hashs
# Not implemented yet ---------------------------------------------------------
#DEBIT_ACCOUNT = False # debit user's account for every mail forwarded
#DEBIT_AUDIT = False # Log mail summary to audit table to see debit reason
#GREYLIST_ENABLED = True # see http://en.wikipedia.org/wiki/Greylisting
