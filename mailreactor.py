# Copyright (c) 2010 Hans Christian v. Stockhausen
# See LICENSE for details.

import datetime
from email.Header import Header
from twisted.mail import smtp
from twisted.mail import relaymanager
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet import defer
from twisted.internet import threads
from twisted.application import internet
from twisted.enterprise import adbapi
from zope.interface import implements
import spf
import srs

from config import *

# Gloabls for database pool and MX DNS lookup ---------------------------------
dbpool = adbapi.ConnectionPool(DBDRIVER, DBCONNECTION_STRING)
mxCalc = relaymanager.MXCalculator()

# Schedule housekeeping job for Greylist --------------------------------------
reactor.callLater(60, lambda: GreylistDB.remove_old_entries())

# Database classes for Greylist and Forwarding rules --------------------------
class GreylistDB(object):

    @staticmethod
    def is_permitted_to_send(user):
        query = """
            SELECT timestamp FROM greylist WHERE
            hostname = '%s'                AND
            ip = '%s'                      AND
            sender_address = '%s'
            """
        deferred = dbpool.runQuery(query % (
            user.helo[0],
            user.helo[1],
            user.orig.addrstr))
        deferred.addCallback(GreylistDB._handle_db_results, user)
        return deferred

    @staticmethod
    def _handle_db_results(results, user):
        if results:
            return True
        else:
            GreylistDB._add_to_grey_list(user)
            raise smtp.SMTPServerError(451, 'Temporary mailbox error.')

    @staticmethod
    def _add_to_grey_list(user):
        query = """
            INSERT INTO greylist (hostname, ip, sender_address, timestamp)
            VALUES ('%s', '%s', '%s', '%s')
            """
        dbpool.runOperation(query % (
            user.helo[0],
            user.helo[1],
            user.orig.addrstr,
            datetime.datetime.now()))

    @staticmethod
    def remove_old_entries():
        date = datetime.datetime.now() - datetime.timedelta(
            seconds=GREYLIST_EXPIRY)
        dbpool.runOperation("DELETE FROM greylist WHERE timestamp < '%s'" % date)
        reactor.callLater(
            GREYLIST_CLEANUP_INTERVAL, 
            GreylistDB.remove_old_entries)


class AliasDB(object):

    @staticmethod
    def get_receiver_for(user):
        query = """
            SELECT target_address, ref_user FROM email_alias WHERE
            source_address = '%s'
            """ % user.dest.addrstr[1:-1]
        deferred = dbpool.runQuery(query)
        deferred.addCallback(AliasDB._handle_db_results, user)
        return deferred

    @staticmethod
    def _handle_db_results(results, user):
        if results:
            return results[0]
        else:
            dbpool.runOperation("INSERT INTO spam_counter (dummy) VALUES ('')")
            raise smtp.SMTPBadRcpt(user)


class CreditsDB(object):

    @staticmethod
    def debit_account(ref_user, amount=1):
        query = """
            UPDATE account_balance SET credits = credits - %i WHERE ref_user =
            '%s' """ % (amount, ref_user)
        dbpool.runOperation(query)
 
 
# SMTP Classes ----------------------------------------------------------------
class MessageForwarder(object):
    implements(smtp.IMessage)

    def __init__(self, from_address, to_address, ref_user):
        self.from_address = from_address
        self.to_address = to_address
        self.ref_user = ref_user
        self.message = []

    def lineReceived(self, line):
        self.message.append(line)

    def connectionLost(self):
        del(self.lines)
        
    def eomReceived(self):
        username, domain = self.to_address.split('@')
        deferred = mxCalc.getMX(domain)
        deferred.addCallback(self._send_mail)
        return deferred

    def _send_mail(self, mxRecord):
        smtp_server = mxRecord.exchange.name
        deferred = smtp.sendmail(
            smtp_server,
            self.from_address,
            [self.to_address],
            '\n'.join(self.message))
        deferred.addCallback(self._handle_send_success)
        deferred.addErrback(self._handle_send_error)
        return deferred
    
    def _handle_send_success(self, status):
        CreditsDB.debit_account(self.ref_user)
        dbpool.runOperation("INSERT INTO messaging_counter (dummy) \
            VALUES ('')")
      
    def _handle_send_error(self, error):
        raise smtp.SMTPServerError(451, error.getErrorMessage())


class ForwardDelivery(object):
    implements(smtp.IMessageDelivery)

    def receivedHeader(self, helo, origin, recipients):
        myHostname, clientIP = helo
        headerValue = "by %s from %s with ESMTP ; %s" % (
            myHostname, clientIP, smtp.rfc822date( ))
        # email.Header.Header used for automatic wrapping of long lines
        return "Received: %s" % Header(headerValue)

    def validateFrom(self, helo, originAddress):
        # Could check SPF here but SPF FAQ recommends to check RCPT TO first.
        # Also we are not checking the greylist just yet as we only want to
        # greylist if the SPF record check does not return 'pass'.
        return originAddress
    
    def validateTo(self, user):
        self.user = user
        self.from_address = user.orig.addrstr
        destination = user.dest.addrstr
        if destination.startswith('SRS') and destination.endswith(HOSTNAME):
            # we are dealing with a bounce message
            try:
                self.to_address = srs.SRS(destination, HOSTNAME).unwrap()
            except srs.SRSError:
                raise smtp.SMTPBadRcpt(user)
            else:
                return self._send_message()
        else:
            return self._lookup_alias()
    
    def _lookup_alias(self):
        deferred = AliasDB.get_receiver_for(self.user)
        deferred.addCallback(self._handle_lookup_alias)
        return deferred
        
    def _handle_lookup_alias(self, response):
        self.to_address, self.ref_user = response
        return self._check_spf()
    
    def _check_spf(self):
        deferred = threads.deferToThread(self._evaluate_spf)
        deferred.addCallback(self._handle_evaluate_spf)
        return deferred

    def _evaluate_spf(self):
        return spf.check(
            h=self.user.helo[0],
            i=self.user.helo[1],
            s=self.user.orig.addrstr[1:-1]) #cut off < and >

    def _handle_evaluate_spf(self, result):
        status, code, reason = result
        self.spf_status = status
        if code == 250:
            if status == 'pass':
                return self._forward_message()
            else:
                deferred = GreylistDB.is_permitted_to_send(self.user)
                deferred.addCallback(self._forward_message)
                return deferred
        else:
            raise smtp.SMTPBadSender(self.user.orig.addrstr)
    
    def _forward_message(self, callback_dummy=None):
        if self.spf_status == 'none':
            return self._send_message()
        else:
            #handle SRS
            self.from_address = srs.SRS(self.from_address, HOSTNAME).wrap()
            return self._send_message()
            
    def _send_message(self):
        return lambda: MessageForwarder(
            from_address=self.from_address,
            to_address=self.to_address,
            ref_user=self.ref_user)


class SMTPFactory(protocol.ServerFactory):
    def buildProtocol(self, addr):
        delivery = ForwardDelivery()
        protocol = smtp.SMTP(delivery)
        protocol.factory = self
        return protocol


# Mailreactor service for .tac file -------------------------------------------
class MailreactorServer(internet.TCPServer):
    def __init__(self):
        internet.TCPServer.__init__(self, SMTP_PORT, SMTPFactory())

# For testing only ------------------------------------------------------------
def main():
    reactor.listenTCP(SMTP_PORT, SMTPFactory())
    reactor.run()

if __name__ == '__main__':
    main()
