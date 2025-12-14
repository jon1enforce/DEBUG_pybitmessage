"""
SMTP server thread
"""
import asyncore
import base64
import email
import logging
import re
import signal
import smtpd
import threading
import time
from email.header import decode_header
from email.parser import Parser
import sqlite3
import traceback

import queues
from addresses import decodeAddress
from bmconfigparser import config
from helper_ackPayload import genAckPayload
from helper_sql import sqlExecute
from network.threads import StoppableThread
from version import softwareVersion
from dbcompat import dbstr

SMTPDOMAIN = "bmaddr.lan"
LISTENPORT = 8425

logger = logging.getLogger('default')
# pylint: disable=attribute-defined-outside-init


class SmtpServerChannelException(Exception):
    """Generic smtp server channel exception."""
    pass


class smtpServerChannel(smtpd.SMTPChannel):
    """Asyncore channel for SMTP protocol (server)"""
    def smtp_EHLO(self, arg):
        """Process an EHLO"""
        logger.debug("DEBUG: SMTP EHLO received with arg: %s", arg)
        if not arg:
            self.push('501 Syntax: HELO hostname')
            logger.debug("DEBUG: EHLO rejected - no argument provided")
            return
        self.push('250-PyBitmessage %s' % softwareVersion)
        self.push('250 AUTH PLAIN')
        logger.debug("DEBUG: EHLO accepted for host: %s", arg)

    def smtp_AUTH(self, arg):
        """Process AUTH"""
        logger.debug("DEBUG: SMTP AUTH received with arg: %s", arg)
        if not arg or arg[0:5] not in ["PLAIN"]:
            self.push('501 Syntax: AUTH PLAIN')
            logger.debug("DEBUG: AUTH rejected - invalid method")
            return
        authstring = arg[6:]
        try:
            decoded = base64.b64decode(authstring)
            correctauth = "\x00" + config.safeGet(
                "bitmessagesettings", "smtpdusername", "") + "\x00" + config.safeGet(
                    "bitmessagesettings", "smtpdpassword", "")
            logger.debug('DEBUG: Auth comparison - correct: %s / received: %s', correctauth, decoded)
            if correctauth == decoded:
                self.auth = True
                self.push('235 2.7.0 Authentication successful')
                logger.debug("DEBUG: Authentication successful")
            else:
                raise SmtpServerChannelException("Auth fail")
        except Exception as e:
            logger.debug("DEBUG: Authentication failed with error: %s", str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
            self.push('501 Authentication fail')

    def smtp_DATA(self, arg):
        """Process DATA"""
        logger.debug("DEBUG: SMTP DATA received")
        if not hasattr(self, "auth") or not self.auth:
            self.push('530 Authentication required')
            logger.debug("DEBUG: DATA rejected - not authenticated")
            return
        logger.debug("DEBUG: DATA accepted - proceeding with message processing")
        smtpd.SMTPChannel.smtp_DATA(self, arg)


class smtpServerPyBitmessage(smtpd.SMTPServer):
    """Asyncore SMTP server class"""
    def handle_accept(self):
        """Accept a connection"""
        logger.debug("DEBUG: Handling new connection attempt")
        pair = self.accept()
        if pair is not None:
            conn, addr = pair
            logger.debug("DEBUG: Accepted connection from: %s", addr)
            self.channel = smtpServerChannel(self, conn, addr)

    def send(self, fromAddress, toAddress, subject, message):
        """Send a bitmessage"""
        # pylint: disable=arguments-differ
        logger.debug("DEBUG: Preparing to send message from %s to %s", fromAddress, toAddress)
        try:
            streamNumber, ripe = decodeAddress(toAddress)[2:]
            stealthLevel = config.safeGetInt('bitmessagesettings', 'ackstealthlevel')
            ackdata = genAckPayload(streamNumber, stealthLevel)
            
            logger.debug("DEBUG: Generated ackdata for stream %s", streamNumber)
            
            sqlExecute(
                '''INSERT INTO sent VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                sqlite3.Binary(b''),
                dbstr(toAddress),
                sqlite3.Binary(ripe),
                dbstr(fromAddress),
                dbstr(subject),
                dbstr(message),
                sqlite3.Binary(ackdata),
                int(time.time()),  # sentTime (this will never change)
                int(time.time()),  # lastActionTime
                0,  # sleepTill time. This will get set when the POW gets done.
                'msgqueued',  # KORREKTUR: Direkt als String, nicht dbstr('msgqueued')
                0,  # retryNumber
                dbstr('sent'),  # folder
                2,  # encodingtype
                # not necessary to have a TTL higher than 2 days
                min(config.getint('bitmessagesettings', 'ttl'), 86400 * 2)
            )
            logger.debug("DEBUG: Message data inserted into database")

            queues.workerQueue.put(('sendmessage', toAddress))
            logger.debug("DEBUG: Message queued for sending to %s", toAddress)
            
        except Exception as e:
            logger.error("DEBUG: Error in send method: %s", str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
            raise

    def decode_header(self, hdr):
        """Email header decoding"""
        logger.debug("DEBUG: Decoding header: %s", hdr)
        ret = []
        try:
            for h in decode_header(self.msg_headers[hdr]):
                if h[1]:
                    ret.append(h[0].decode(h[1]))
                else:
                    ret.append(h[0].decode("utf-8", errors='replace'))
            logger.debug("DEBUG: Decoded header result: %s", ret)
        except Exception as e:
            logger.error("DEBUG: Error decoding header %s: %s", hdr, str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
            raise
        return ret

    def process_message(self, peer, mailfrom, rcpttos, data):
        """Process an email"""
        # pylint: disable=too-many-locals, too-many-branches
        logger.debug("DEBUG: Processing message from %s to %s", mailfrom, rcpttos)
        p = re.compile(".*<([^>]+)>")
        if not hasattr(self.channel, "auth") or not self.channel.auth:
            logger.error('DEBUG: Missing or invalid auth for message processing')
            return
        try:
            self.msg_headers = Parser().parsestr(data)
            logger.debug("DEBUG: Successfully parsed message headers")
        except Exception as e:
            logger.error('DEBUG: Invalid headers in message: %s', str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
            return

        try:
            sender, domain = p.sub(r'\1', mailfrom).split("@")
            logger.debug("DEBUG: Extracted sender: %s, domain: %s", sender, domain)
            if domain != SMTPDOMAIN:
                raise Exception("Bad domain %s" % domain)
            if sender not in config.addresses():
                raise Exception("Nonexisting user %s" % sender)
            logger.debug("DEBUG: Valid sender: %s", sender)
        except Exception as err:
            logger.debug('DEBUG: Bad envelope from %s: %r', mailfrom, err)
            try:
                msg_from = self.decode_header("from")
                msg_from = p.sub(r'\1', self.decode_header("from")[0])
                sender, domain = msg_from.split("@")
                logger.debug("DEBUG: Trying header From: %s@%s", sender, domain)
                if domain != SMTPDOMAIN:
                    raise Exception("Bad domain %s" % domain)
                if sender not in config.addresses():
                    raise Exception("Nonexisting user %s" % sender)
                logger.debug("DEBUG: Valid sender from headers: %s", sender)
            except Exception as err:
                logger.error('DEBUG: Bad headers from %s: %r', msg_from, err)
                logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
                return

        try:
            msg_subject = self.decode_header('subject')[0]
            logger.debug("DEBUG: Message subject: %s", msg_subject)
        except Exception as e:
            msg_subject = "Subject missing..."
            logger.debug("DEBUG: No subject found, using default. Error: %s", str(e))

        try:
            msg_tmp = email.message_from_string(data)
            body = u''
            for part in msg_tmp.walk():
                if part and part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=1).decode(part.get_content_charset('utf-8'), errors='replace')
            logger.debug("DEBUG: Extracted message body (first 100 chars): %s", body[:100])
        except Exception as e:
            logger.error("DEBUG: Error processing message body: %s", str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
            return

        for to in rcpttos:
            try:
                rcpt, domain = p.sub(r'\1', to).split("@")
                logger.debug("DEBUG: Processing recipient: %s@%s", rcpt, domain)
                if domain != SMTPDOMAIN:
                    raise Exception("Bad domain %s" % domain)
                logger.debug(
                    'DEBUG: Sending message from %s to %s about %s', sender, rcpt, msg_subject)
                self.send(sender, rcpt, msg_subject, body)
                logger.info('DEBUG: Successfully relayed message from %s to %s', sender, rcpt)
            except Exception as err:
                logger.error('DEBUG: Error processing recipient %s: %r', to, err)
                logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
                continue
        return


class smtpServer(StoppableThread):
    """SMTP server thread"""
    def __init__(self, _=None):
        super(smtpServer, self).__init__(name="smtpServerThread")
        logger.debug("DEBUG: Initializing SMTP server on port %d", LISTENPORT)
        self.server = smtpServerPyBitmessage(('127.0.0.1', LISTENPORT), None)
        logger.debug("DEBUG: SMTP server initialized")

    def stopThread(self):
        logger.debug("DEBUG: Stopping SMTP server thread")
        super(smtpServer, self).stopThread()
        self.server.close()
        logger.debug("DEBUG: SMTP server thread stopped")
        return

    def run(self):
        logger.debug("DEBUG: Starting SMTP server asyncore loop")
        asyncore.loop(1)
        logger.debug("DEBUG: SMTP server asyncore loop ended")


def signals(_, __):
    """Signal handler"""
    logger.warning('DEBUG: Received termination signal')
    for thread in threading.enumerate():
        if thread.isAlive() and isinstance(thread, StoppableThread):
            logger.debug("DEBUG: Stopping thread: %s", thread.name)
            thread.stopThread()


def runServer():
    """Run SMTP server as a standalone python process"""
    logger.warning('DEBUG: Starting SMTP server thread')
    smtpThread = smtpServer()
    smtpThread.start()
    signal.signal(signal.SIGINT, signals)
    signal.signal(signal.SIGTERM, signals)
    logger.warning('DEBUG: SMTP server running and processing messages')
    smtpThread.join()
    logger.warning('DEBUG: SMTP server shutdown complete')


if __name__ == "__main__":
    runServer()
