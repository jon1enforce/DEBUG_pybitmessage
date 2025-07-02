"""
addressGenerator thread class definition
"""

import time
from binascii import hexlify

from six.moves import configparser, queue

import defaults
import highlevelcrypto
import queues
import shared
import state
from addresses import decodeAddress, encodeAddress, encodeVarint
from bmconfigparser import config
from network import StoppableThread
from tr import _translate


class AddressGeneratorException(Exception):
    '''Generic AddressGenerator exception'''
    pass


class addressGenerator(StoppableThread):
    """A thread for creating addresses"""

    name = "addressGenerator"

    def stopThread(self):
        """Tell the thread to stop putting a special command to it's queue"""
        print("DEBUG: Stopping addressGenerator thread")
        try:
            queues.addressGeneratorQueue.put(("stopThread", "data"))
        except queue.Full:
            self.logger.error('addressGeneratorQueue is Full')
            print("DEBUG: addressGeneratorQueue is full, couldn't put stop command")

        super(addressGenerator, self).stopThread()

    def run(self):
        """
        Process the requests for addresses generation
        from `.queues.addressGeneratorQueue`
        """
        # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        # pylint: disable=too-many-nested-blocks

        print("DEBUG: addressGenerator thread started")
        while state.shutdown == 0:
            queueValue = queues.addressGeneratorQueue.get()
            print(f"DEBUG: Processing queue value: {queueValue[0]}")
            
            nonceTrialsPerByte = 0
            payloadLengthExtraBytes = 0
            live = True
            
            if queueValue[0] == 'createChan':
                print("DEBUG: Processing createChan command")
                command, addressVersionNumber, streamNumber, label, \
                    deterministicPassphrase, live = queueValue
                eighteenByteRipe = False
                numberOfAddressesToMake = 1
                numberOfNullBytesDemandedOnFrontOfRipeHash = 1
            elif queueValue[0] == 'joinChan':
                print("DEBUG: Processing joinChan command")
                command, chanAddress, label, deterministicPassphrase, \
                    live = queueValue
                eighteenByteRipe = False
                addressVersionNumber = decodeAddress(chanAddress)[1]
                streamNumber = decodeAddress(chanAddress)[2]
                numberOfAddressesToMake = 1
                numberOfNullBytesDemandedOnFrontOfRipeHash = 1
            elif len(queueValue) == 7:
                print("DEBUG: Processing 7-value command")
                command, addressVersionNumber, streamNumber, label, \
                    numberOfAddressesToMake, deterministicPassphrase, \
                    eighteenByteRipe = queueValue

                numberOfNullBytesDemandedOnFrontOfRipeHash = \
                    config.safeGetInt(
                        'bitmessagesettings',
                        'numberofnullbytesonaddress',
                        2 if eighteenByteRipe else 1
                    )
            elif len(queueValue) == 9:
                print("DEBUG: Processing 9-value command")
                command, addressVersionNumber, streamNumber, label, \
                    numberOfAddressesToMake, deterministicPassphrase, \
                    eighteenByteRipe, nonceTrialsPerByte, \
                    payloadLengthExtraBytes = queueValue

                numberOfNullBytesDemandedOnFrontOfRipeHash = \
                    config.safeGetInt(
                        'bitmessagesettings',
                        'numberofnullbytesonaddress',
                        2 if eighteenByteRipe else 1
                    )
            elif queueValue[0] == 'stopThread':
                print("DEBUG: Received stopThread command")
                break
            else:
                self.logger.error(
                    'Programming error: A structure with the wrong number'
                    ' of values was passed into the addressGeneratorQueue.'
                    ' Here is the queueValue: %r\n', queueValue)
                print(f"DEBUG: Error - invalid queue value: {queueValue}")
            
            if addressVersionNumber < 3 or addressVersionNumber > 4:
                self.logger.error(
                    'Program error: For some reason the address generator'
                    ' queue has been given a request to create at least'
                    ' one version %s address which it cannot do.\n',
                    addressVersionNumber)
                print(f"DEBUG: Error - invalid address version: {addressVersionNumber}")
            
            if nonceTrialsPerByte == 0:
                nonceTrialsPerByte = config.getint(
                    'bitmessagesettings', 'defaultnoncetrialsperbyte')
                print(f"DEBUG: Using default nonceTrialsPerByte: {nonceTrialsPerByte}")
            
            if nonceTrialsPerByte < \
                    defaults.networkDefaultProofOfWorkNonceTrialsPerByte:
                nonceTrialsPerByte = \
                    defaults.networkDefaultProofOfWorkNonceTrialsPerByte
                print(f"DEBUG: Adjusted nonceTrialsPerByte to network default: {nonceTrialsPerByte}")
            
            if payloadLengthExtraBytes == 0:
                payloadLengthExtraBytes = config.getint(
                    'bitmessagesettings', 'defaultpayloadlengthextrabytes')
                print(f"DEBUG: Using default payloadLengthExtraBytes: {payloadLengthExtraBytes}")
            
            if payloadLengthExtraBytes < \
                    defaults.networkDefaultPayloadLengthExtraBytes:
                payloadLengthExtraBytes = \
                    defaults.networkDefaultPayloadLengthExtraBytes
                print(f"DEBUG: Adjusted payloadLengthExtraBytes to network default: {payloadLengthExtraBytes}")
            
            if command == 'createRandomAddress':
                print("DEBUG: Processing createRandomAddress command")
                queues.UISignalQueue.put((
                    'updateStatusBar',
                    _translate(
                        "MainWindow", "Generating one new address")
                ))
                # This next section is a little bit strange. We're going
                # to generate keys over and over until we find one
                # that starts with either \x00 or \x00\x00. Then when
                # we pack them into a Bitmessage address, we won't store
                # the \x00 or \x00\x00 bytes thus making the address shorter.
                startTime = time.time()
                numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix = 0
                privSigningKey, pubSigningKey = highlevelcrypto.random_keys()
                print("DEBUG: Starting random address generation loop")
                
                while True:
                    numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix += 1
                    potentialPrivEncryptionKey, potentialPubEncryptionKey = \
                        highlevelcrypto.random_keys()
                    ripe = highlevelcrypto.to_ripe(
                        pubSigningKey, potentialPubEncryptionKey)
                    if (
                        ripe[:numberOfNullBytesDemandedOnFrontOfRipeHash]
                        == b'\x00' * numberOfNullBytesDemandedOnFrontOfRipeHash
                    ):
                        print("DEBUG: Found address with matching RIPE prefix")
                        break
                
                self.logger.info(
                    'Generated address with ripe digest: %s', hexlify(ripe))
                print(f"DEBUG: Generated RIPE: {hexlify(ripe)}")
                
                try:
                    self.logger.info(
                        'Address generator calculated %s addresses at %s'
                        ' addresses per second before finding one with'
                        ' the correct ripe-prefix.',
                        numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix,
                        numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix
                        / (time.time() - startTime))
                    print(f"DEBUG: Address generation performance: {numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix / (time.time() - startTime)} addresses/sec")
                except ZeroDivisionError:
                    # The user must have a pretty fast computer.
                    # time.time() - startTime equaled zero.
                    print("DEBUG: Address generation was extremely fast (division by zero)")
                    pass
                
                address = encodeAddress(
                    addressVersionNumber, streamNumber, ripe)
                print(f"DEBUG: Generated address: {address}")

                privSigningKeyWIF = highlevelcrypto.encodeWalletImportFormat(
                    privSigningKey)
                privEncryptionKeyWIF = highlevelcrypto.encodeWalletImportFormat(
                    potentialPrivEncryptionKey)

                config.add_section(address)
                config.set(address, 'label', label)
                config.set(address, 'enabled', 'true')
                config.set(address, 'decoy', 'false')
                config.set(address, 'noncetrialsperbyte', str(
                    nonceTrialsPerByte))
                config.set(address, 'payloadlengthextrabytes', str(
                    payloadLengthExtraBytes))
                config.set(
                    address, 'privsigningkey', privSigningKeyWIF.decode())
                config.set(
                    address, 'privencryptionkey',
                    privEncryptionKeyWIF.decode())
                config.save()
                print("DEBUG: Saved new address to config")

                # The API and the join and create Chan functionality
                # both need information back from the address generator.
                queues.apiAddressGeneratorReturnQueue.put(address)
                print("DEBUG: Sent address to API return queue")

                queues.UISignalQueue.put((
                    'updateStatusBar',
                    _translate(
                        "MainWindow",
                        "Done generating address. Doing work necessary"
                        " to broadcast it...")
                ))
                queues.UISignalQueue.put(('writeNewAddressToTable', (
                    label, address, streamNumber)))
                print("DEBUG: Updated UI with new address")
                
                shared.reloadMyAddressHashes()
                print("DEBUG: Reloaded address hashes")
                
                if addressVersionNumber == 3:
                    print("DEBUG: Queueing V3 pubkey broadcast")
                    queues.workerQueue.put(('sendOutOrStoreMyV3Pubkey', ripe))
                elif addressVersionNumber == 4:
                    print("DEBUG: Queueing V4 pubkey broadcast")
                    queues.workerQueue.put(('sendOutOrStoreMyV4Pubkey', address))

            elif command in (
                'createDeterministicAddresses', 'createChan',
                'getDeterministicAddress', 'joinChan'
            ):
                print(f"DEBUG: Processing deterministic address command: {command}")
                if not deterministicPassphrase:
                    self.logger.warning(
                        'You are creating deterministic'
                        ' address(es) using a blank passphrase.'
                        ' Bitmessage will do it but it is rather stupid.')
                    print("DEBUG: Warning - using blank passphrase for deterministic address")
                
                if command == 'createDeterministicAddresses':
                    queues.UISignalQueue.put((
                        'updateStatusBar',
                        _translate(
                            "MainWindow",
                            "Generating {0} new addresses."
                        ).format(str(numberOfAddressesToMake))
                    ))
                    print(f"DEBUG: Generating {numberOfAddressesToMake} deterministic addresses")
                
                signingKeyNonce = 0
                encryptionKeyNonce = 1
                # We fill out this list no matter what although we only
                # need it if we end up passing the info to the API.
                listOfNewAddressesToSendOutThroughTheAPI = []
                print("DEBUG: Starting deterministic address generation loop")

                for _ in range(numberOfAddressesToMake):
                    # This next section is a little bit strange. We're
                    # going to generate keys over and over until we find
                    # one that has a RIPEMD hash that starts with either
                    # \x00 or \x00\x00. Then when we pack them into a
                    # Bitmessage address, we won't store the \x00 or
                    # \x00\x00 bytes thus making the address shorter.
                    startTime = time.time()
                    numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix = 0
                    print("DEBUG: Starting RIPE prefix search loop")
                    
                    while True:
                        numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix += 1
                        potentialPrivSigningKey, potentialPubSigningKey = \
                            highlevelcrypto.deterministic_keys(
                                deterministicPassphrase,
                                encodeVarint(signingKeyNonce))
                        potentialPrivEncryptionKey, potentialPubEncryptionKey = \
                            highlevelcrypto.deterministic_keys(
                                deterministicPassphrase,
                                encodeVarint(encryptionKeyNonce))

                        signingKeyNonce += 2
                        encryptionKeyNonce += 2
                        ripe = highlevelcrypto.to_ripe(
                            potentialPubSigningKey, potentialPubEncryptionKey)
                        if (
                            ripe[:numberOfNullBytesDemandedOnFrontOfRipeHash]
                            == b'\x00' * numberOfNullBytesDemandedOnFrontOfRipeHash
                        ):
                            print("DEBUG: Found address with matching RIPE prefix")
                            break

                    self.logger.info(
                        'Generated address with ripe digest: %s', hexlify(ripe))
                    print(f"DEBUG: Generated RIPE: {hexlify(ripe)}")
                    
                    try:
                        self.logger.info(
                            'Address generator calculated %s addresses'
                            ' at %s addresses per second before finding'
                            ' one with the correct ripe-prefix.',
                            numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix,
                            numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix
                            / (time.time() - startTime)
                        )
                        print(f"DEBUG: Address generation performance: {numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix / (time.time() - startTime)} addresses/sec")
                    except ZeroDivisionError:
                        # The user must have a pretty fast computer.
                        # time.time() - startTime equaled zero.
                        print("DEBUG: Address generation was extremely fast (division by zero)")
                        pass
                    
                    address = encodeAddress(
                        addressVersionNumber, streamNumber, ripe)
                    print(f"DEBUG: Generated address: {address}")

                    saveAddressToDisk = True
                    # If we are joining an existing chan, let us check
                    # to make sure it matches the provided Bitmessage address
                    if command == 'joinChan':
                        print("DEBUG: Verifying chan address match")
                        if address != chanAddress:
                            listOfNewAddressesToSendOutThroughTheAPI.append(
                                'chan name does not match address')
                            saveAddressToDisk = False
                            print("DEBUG: Chan address mismatch")
                    if command == 'getDeterministicAddress':
                        saveAddressToDisk = False
                        print("DEBUG: getDeterministicAddress - not saving to disk")

                    if saveAddressToDisk and live:
                        privSigningKeyWIF = \
                            highlevelcrypto.encodeWalletImportFormat(
                                potentialPrivSigningKey)
                        privEncryptionKeyWIF = \
                            highlevelcrypto.encodeWalletImportFormat(
                                potentialPrivEncryptionKey)

                        try:
                            config.add_section(address)
                            addressAlreadyExists = False
                            print("DEBUG: Added new address section to config")
                        except configparser.DuplicateSectionError:
                            addressAlreadyExists = True
                            print("DEBUG: Address already exists in config")

                        if addressAlreadyExists:
                            self.logger.info(
                                '%s already exists. Not adding it again.',
                                address
                            )
                            queues.UISignalQueue.put((
                                'updateStatusBar',
                                _translate(
                                    "MainWindow",
                                    "{0} is already in 'Your Identities'."
                                    " Not adding it again."
                                ).format(address)
                            ))
                            print("DEBUG: Skipping duplicate address")
                        else:
                            self.logger.debug('label: %s', label)
                            config.set(address, 'label', label)
                            config.set(address, 'enabled', 'true')
                            config.set(address, 'decoy', 'false')
                            if command in ('createChan', 'joinChan'):
                                config.set(address, 'chan', 'true')
                                print("DEBUG: Marking address as chan")
                            config.set(
                                address, 'noncetrialsperbyte',
                                str(nonceTrialsPerByte))
                            config.set(
                                address, 'payloadlengthextrabytes',
                                str(payloadLengthExtraBytes))
                            config.set(
                                address, 'privsigningkey',
                                privSigningKeyWIF.decode())
                            config.set(
                                address, 'privencryptionkey',
                                privEncryptionKeyWIF.decode())
                            config.save()
                            print("DEBUG: Saved address details to config")

                            queues.UISignalQueue.put(
                                'writeNewAddressToTable',
                                (label, address, str(streamNumber))
                            )
                            listOfNewAddressesToSendOutThroughTheAPI.append(
                                address)
                            shared.myECCryptorObjects[ripe] = \
                                highlevelcrypto.makeCryptor(
                                    hexlify(potentialPrivEncryptionKey))
                            shared.myAddressesByHash[ripe] = address
                            tag = highlevelcrypto.double_sha512(
                                encodeVarint(addressVersionNumber)
                                + encodeVarint(streamNumber) + ripe
                            )[32:]
                            shared.myAddressesByTag[tag] = address
                            print("DEBUG: Updated shared address dictionaries")
                            
                            if addressVersionNumber == 3:
                                # If this is a chan address,
                                # the worker thread won't send out
                                # the pubkey over the network.
                                print("DEBUG: Queueing V3 pubkey broadcast")
                                queues.workerQueue.put(('sendOutOrStoreMyV3Pubkey', ripe))
                            elif addressVersionNumber == 4:
                                print("DEBUG: Queueing V4 pubkey broadcast")
                                queues.workerQueue.put(('sendOutOrStoreMyV4Pubkey', address))
                            queues.UISignalQueue.put((
                                'updateStatusBar',
                                _translate(
                                    "MainWindow", "Done generating address")
                            ))
                    elif saveAddressToDisk and not live \
                            and not config.has_section(address):
                        listOfNewAddressesToSendOutThroughTheAPI.append(
                            address)
                        print("DEBUG: Added address to API list (non-live)")

                # Done generating addresses.
                if command in (
                    'createDeterministicAddresses', 'createChan', 'joinChan'
                ):
                    print("DEBUG: Sending address list to API return queue")
                    queues.apiAddressGeneratorReturnQueue.put(
                        listOfNewAddressesToSendOutThroughTheAPI)
                elif command == 'getDeterministicAddress':
                    print("DEBUG: Sending single address to API return queue")
                    queues.apiAddressGeneratorReturnQueue.put(address)
            else:
                raise AddressGeneratorException(
                    "Error in the addressGenerator thread. Thread was"
                    + " given a command it could not understand: " + command)
                print(f"DEBUG: Error - unknown command: {command}")
            
            queues.addressGeneratorQueue.task_done()
            print("DEBUG: Finished processing queue item")
