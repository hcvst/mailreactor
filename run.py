# Copyright (c) 2010 Hans Christian v. Stockhausen.
# See LICENSE for details.

import sys
sys.path.append('/home/ubuntu/mailreactor')

from twisted.application import service
import mailreactor
from config import UID, GID

application = service.Application("Mailreactor", UID, GID)
service = mailreactor.MailreactorServer()
service.setServiceParent(application)
