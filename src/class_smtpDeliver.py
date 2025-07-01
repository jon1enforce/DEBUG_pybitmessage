"""
SMTP client thread for delivering emails
"""
# pylint: disable=unused-variable

import smtplib
from six.moves.urllib import parse as urlparse
from email.header import Header
from six.moves import email_mime_text
import logging
import traceback

import queues
import state
from bmconfigparser import config
from network.threads import StoppableThread

SMTPDOMAIN = "bmaddr.lan"

logger = logging.getLogger('default')


class smtpDeliver(StoppableThread):
    """SMTP client thread for delivery"""
    name = "smtpDeliver"
    _instance = None

    def stopThread(self):
        """Relay shutdown instruction"""
        logger.debug("DEBUG: Stopping SMTP deliver thread")
        queues.UISignalQueue.put(("stopThread", "data"))
        super(smtpDeliver, self).stopThread()
        logger.debug("DEBUG: SMTP deliver thread stopped")

    @classmethod
    def get(cls):
        """(probably) Singleton functionality"""
        logger.debug("DEBUG: Getting SMTP deliver instance")
        if not cls._instance:
            logger.debug("DEBUG: Creating new SMTP deliver instance")
            cls._instance = smtpDeliver()
        return cls._instance

    def run(self):
        # pylint: disable=too-many-branches,too-many-statements,too-many-locals
        # pylint: disable=deprecated-lambda
        logger.debug("DEBUG: Starting SMTP deliver thread main loop")
        while state.shutdown == 0:
            try:
                command, data = queues.UISignalQueue.get()
                logger.debug("DEBUG: Received command: %s", command)

                if command == 'writeNewAddressToTable':
                    label, address, streamNumber = data
                    logger.debug("DEBUG: Processing writeNewAddressToTable - Label: %s, Address: %s, Stream: %s",
                               label, address, streamNumber)

                elif command == 'updateStatusBar':
                    logger.debug("DEBUG: Processing updateStatusBar command")
                    pass

                elif command == 'updateSentItemStatusByToAddress':
                    toAddress, message = data
                    logger.debug("DEBUG: Updating sent item status for address: %s", toAddress)

                elif command == 'updateSentItemStatusByAckdata':
                    ackData, message = data
                    logger.debug("DEBUG: Updating sent item status for ackdata: %s", ackData)

                elif command == 'displayNewInboxMessage':
                    inventoryHash, toAddress, fromAddress, subject, body = data
                    logger.debug("DEBUG: Processing new inbox message - To: %s, From: %s, Subject: %s",
                               toAddress, fromAddress, subject)
                    
                    dest = config.safeGet("bitmessagesettings", "smtpdeliver", '')
                    logger.debug("DEBUG: SMTP delivery destination config: %s", dest)
                    
                    if dest == '':
                        logger.debug("DEBUG: No SMTP delivery destination configured, skipping")
                        continue
                    
                    try:
                        logger.debug("DEBUG: Parsing SMTP destination URL")
                        u = urlparse.urlparse(dest)
                        logger.debug("DEBUG: URL components - Scheme: %s, Host: %s, Port: %s, Path: %s",
                                   u.scheme, u.hostname, u.port, u.path)
                        
                        to = urlparse.parse_qs(u.query)['to']
                        logger.debug("DEBUG: Extracted recipient from query: %s", to)
                        
                        logger.debug("DEBUG: Connecting to SMTP server %s:%s", u.hostname, u.port)
                        client = smtplib.SMTP(u.hostname, u.port)
                        logger.debug("DEBUG: SMTP connection established")
                        
                        msg = email_mime_text(body, 'plain', 'utf-8')
                        msg['Subject'] = Header(subject, 'utf-8')
                        msg['From'] = fromAddress + '@' + SMTPDOMAIN
                        logger.debug("DEBUG: Created email message - From: %s, Subject: %s",
                                   msg['From'], subject)
                        
                        toLabel = map(
                            lambda y: config.safeGet(y, "label"),
                            filter(
                                lambda x: x == toAddress, config.addresses())
                        )
                        
                        if toLabel:
                            msg['To'] = "\"%s\" <%s>" % (Header(toLabel[0], 'utf-8'), toAddress + '@' + SMTPDOMAIN)
                            logger.debug("DEBUG: Using labeled recipient: %s", toLabel[0])
                        else:
                            msg['To'] = toAddress + '@' + SMTPDOMAIN
                            logger.debug("DEBUG: Using unlabeled recipient address")
                        
                        logger.debug("DEBUG: Starting SMTP protocol")
                        client.ehlo()
                        client.starttls()
                        client.ehlo()
                        
                        logger.debug("DEBUG: Sending email message")
                        client.sendmail(msg['From'], [to], msg.as_string())
                        logger.info('DEBUG: Successfully delivered via SMTP to %s through %s:%i',
                                  to, u.hostname, u.port)
                        
                        client.quit()
                        logger.debug("DEBUG: Closed SMTP connection")
                        
                    except Exception as e:
                        logger.error('DEBUG: SMTP delivery error: %s', str(e))
                        logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

                elif command == 'displayNewSentMessage':
                    toAddress, fromLabel, fromAddress, subject, message, ackdata = data
                    logger.debug("DEBUG: Processing new sent message - To: %s, From: %s, Subject: %s",
                               toAddress, fromAddress, subject)

                elif command in [
                    'updateNetworkStatusTab',
                    'updateNumberOfMessagesProcessed',
                    'updateNumberOfPubkeysProcessed',
                    'updateNumberOfBroadcastsProcessed',
                    'setStatusIcon',
                    'changedInboxUnread',
                    'rerenderMessagelistFromLabels',
                    'rerenderMessagelistToLabels',
                    'rerenderAddressBook',
                    'rerenderSubscriptions',
                    'rerenderBlackWhiteList',
                    'removeInboxRowByMsgid',
                    'newVersionAvailable'
                ]:
                    logger.debug("DEBUG: Processing command: %s", command)
                    pass

                elif command == 'alert':
                    title, text, exitAfterUserClicksOk = data
                    logger.debug("DEBUG: Processing alert - Title: %s, Text: %s", title, text)

                elif command == 'stopThread':
                    logger.debug("DEBUG: Received stopThread command, breaking loop")
                    break

                else:
                    logger.warning('DEBUG: Unrecognized command sent to smtpDeliver: %s', command)

            except Exception as e:
                logger.error('DEBUG: Error in SMTP deliver main loop: %s', str(e))
                logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

        logger.debug("DEBUG: Exiting SMTP deliver thread main loop")
