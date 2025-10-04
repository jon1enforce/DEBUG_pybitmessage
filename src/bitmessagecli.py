#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines,global-statement,too-many-branches,too-many-statements,inconsistent-return-statements
# pylint: disable=too-many-nested-blocks,too-many-locals,protected-access,too-many-arguments,too-many-function-args
# pylint: disable=no-member
"""
Created by Adam Melton (.dok) referenceing https://bitmessage.org/wiki/API_Reference for API documentation
Distributed under the MIT/X11 software license. See http://www.opensource.org/licenses/mit-license.php.

This is an example of a daemon client for PyBitmessage 0.6.2, by .dok (Version 0.3.1) , modified

TODO: fix the following (currently ignored) violations:
"""

import datetime
import imghdr
import json
import ntpath
import os
import socket
import sys
import time
from six.moves import xmlrpc_client as xmlrpclib
from six.moves import input as raw_input

from bmconfigparser import config

print("DEBUG: Initializing global variables")
api = ''
keysName = 'keys.dat'
keysPath = 'keys.dat'
usrPrompt = 0  # 0 = First Start, 1 = prompt, 2 = no prompt if the program is starting up
knownAddresses = dict()

def userInput(message):
    """Checks input for exit or quit. Also formats for input, etc"""
    global usrPrompt
    print("DEBUG: userInput() called with message:", message)

    print('\n' + message)
    uInput = raw_input('> ')
    print("DEBUG: User input received:", uInput)

    if uInput.lower() == 'exit':  # Returns the user to the main menu
        print("DEBUG: User chose to exit to main menu")
        usrPrompt = 1
        main()

    elif uInput.lower() == 'quit':  # Quits the program
        print('\n     Bye\n')
        print("DEBUG: User chose to quit program")
        sys.exit(0)

    else:
        print("DEBUG: Returning user input:", uInput)
        return uInput

def restartBmNotify():
    """Prompt the user to restart Bitmessage"""
    print('\n     *******************************************************************')
    print('     WARNING: If Bitmessage is running locally, you must restart it now.')
    print('     *******************************************************************\n')
    print("DEBUG: Displayed restart Bitmessage notification")

# Begin keys.dat interactions

def lookupAppdataFolder():
    """gets the appropriate folders for the .dat files depending on the OS. Taken from bitmessagemain.py"""
    print("DEBUG: lookupAppdataFolder() called")
    
    APPNAME = "PyBitmessage"
    if sys.platform == 'darwin':
        if "HOME" in os.environ:
            dataFolder = os.path.join(os.environ["HOME"], "Library/Application support/", APPNAME) + '/'
        else:
            print(
                '     Could not find home folder, please report '
                'this message and your OS X version to the Daemon Github.')
            print("DEBUG: Error - Could not find home folder on macOS")
            sys.exit(1)

    elif 'win32' in sys.platform or 'win64' in sys.platform:
        dataFolder = os.path.join(os.environ['APPDATA'], APPNAME) + '\\'
    else:
        dataFolder = os.path.expanduser(os.path.join("~", ".config/" + APPNAME + "/"))
    
    print("DEBUG: Determined appdata folder:", dataFolder)
    return dataFolder

def configInit():
    """Initialised the configuration"""
    print("DEBUG: configInit() called")
    
    config.add_section('bitmessagesettings')
    # Sets the bitmessage port to stop the warning about the api not properly
    # being setup. This is in the event that the keys.dat is in a different
    # directory or is created locally to connect to a machine remotely.
    config.set('bitmessagesettings', 'port', '8444')
    config.set('bitmessagesettings', 'apienabled', 'true')  # Sets apienabled to true in keys.dat

    with safe_open(keysName, 'wb') as configfile:
        config.write(configfile)

    print('\n     ' + str(keysName) + ' Initalized in the same directory as daemon.py')
    print('     You will now need to configure the ' + str(keysName) + ' file.\n')
    print("DEBUG: Configuration initialized and saved to", keysName)

def apiInit(apiEnabled):
    """Initialise the API"""
    global usrPrompt
    print("DEBUG: apiInit() called with apiEnabled:", apiEnabled)
    
    config.read(keysPath)

    if apiEnabled is False:  # API information there but the api is disabled.
        uInput = userInput("The API is not enabled. Would you like to do that now, (Y)es or (N)o?").lower()
        print("DEBUG: User response to enable API:", uInput)

        if uInput == "y":
            config.set('bitmessagesettings', 'apienabled', 'true')  # Sets apienabled to true in keys.dat
            with safe_open(keysPath, 'wb') as configfile:
                config.write(configfile)

            print('Done')
            restartBmNotify()
            print("DEBUG: API enabled in configuration")
            return True

        elif uInput == "n":
            print('     \n************************************************************')
            print('            Daemon will not work when the API is disabled.       ')
            print('     Please refer to the Bitmessage Wiki on how to setup the API.')
            print('     ************************************************************\n')
            usrPrompt = 1
            print("DEBUG: User chose not to enable API")
            main()

        else:
            print('\n     Invalid Entry\n')
            usrPrompt = 1
            print("DEBUG: Invalid user input")
            main()

    elif apiEnabled:  # API correctly setup
        # Everything is as it should be
        print("DEBUG: API is already properly configured")
        return True

    else:  # API information was not present.
        print('\n     ' + str(keysPath) + ' not properly configured!\n')
        uInput = userInput("Would you like to do this now, (Y)es or (N)o?").lower()
        print("DEBUG: User response to configure API:", uInput)

        if uInput == "y":  # User said yes, initalize the api by writing these values to the keys.dat file
            print(' ')

            apiUsr = userInput("API Username")
            apiPwd = userInput("API Password")
            apiPort = userInput("API Port")
            apiEnabled = userInput("API Enabled? (True) or (False)").lower()
            daemon = userInput("Daemon mode Enabled? (True) or (False)").lower()

            print("DEBUG: Collected API configuration - Username:", apiUsr, "Port:", apiPort, "Enabled:", apiEnabled, "Daemon:", daemon)

            if (daemon != 'true' and daemon != 'false'):
                print('\n     Invalid Entry for Daemon.\n')
                uInput = 1
                print("DEBUG: Invalid daemon mode entered")
                main()

            print('     -----------------------------------\n')

            # sets the bitmessage port to stop the warning about the api not properly
            # being setup. This is in the event that the keys.dat is in a different
            # directory or is created locally to connect to a machine remotely.
            config.set('bitmessagesettings', 'port', '8444')
            config.set('bitmessagesettings', 'apienabled', 'true')
            config.set('bitmessagesettings', 'apiport', apiPort)
            config.set('bitmessagesettings', 'apiinterface', '127.0.0.1')
            config.set('bitmessagesettings', 'apiusername', apiUsr)
            config.set('bitmessagesettings', 'apipassword', apiPwd)
            config.set('bitmessagesettings', 'daemon', daemon)
            with safe_open(keysPath, 'wb') as configfile:
                config.write(configfile)

            print('\n     Finished configuring the keys.dat file with API information.\n')
            restartBmNotify()
            print("DEBUG: API configuration saved to keys.dat")
            return True

        elif uInput == "n":
            print('\n     ***********************************************************')
            print('     Please refer to the Bitmessage Wiki on how to setup the API.')
            print('     ***********************************************************\n')
            usrPrompt = 1
            print("DEBUG: User chose not to configure API")
            main()
        else:
            print('     \nInvalid entry\n')
            usrPrompt = 1
            print("DEBUG: Invalid user input")
            main()

def apiData():
    """TBC"""
    global keysName
    global keysPath
    global usrPrompt
    print("DEBUG: apiData() called")

    config.read(keysPath)  # First try to load the config file (the keys.dat file) from the program directory

    try:
        config.get('bitmessagesettings', 'port')
        appDataFolder = ''
        print("DEBUG: Found keys.dat in program directory")
    except:  # noqa:E722
        # Could not load the keys.dat file in the program directory. Perhaps it is in the appdata directory.
        print("DEBUG: keys.dat not found in program directory, checking appdata directory")
        appDataFolder = lookupAppdataFolder()
        keysPath = appDataFolder + keysPath
        config.read(keysPath)

        try:
            config.get('bitmessagesettings', 'port')
            print("DEBUG: Found keys.dat in appdata directory")
        except:  # noqa:E722
            # keys.dat was not there either, something is wrong.
            print('\n     ******************************************************************')
            print('     There was a problem trying to access the Bitmessage keys.dat file')
            print('                    or keys.dat is not set up correctly')
            print('       Make sure that daemon is in the same directory as Bitmessage. ')
            print('     ******************************************************************\n')
            print("DEBUG: keys.dat not found in either location")

            uInput = userInput("Would you like to create a keys.dat in the local directory, (Y)es or (N)o?").lower()
            print("DEBUG: User response to create keys.dat:", uInput)

            if uInput in ("y", "yes"):
                configInit()
                keysPath = keysName
                usrPrompt = 0
                print("DEBUG: Created new keys.dat in local directory")
                main()
            elif uInput in ("n", "no"):
                print('\n     Trying Again.\n')
                usrPrompt = 0
                print("DEBUG: User chose not to create keys.dat, trying again")
                main()
            else:
                print('\n     Invalid Input.\n')
                print("DEBUG: Invalid user input")

            usrPrompt = 1
            main()

    try:  # checks to make sure that everyting is configured correctly. Excluding apiEnabled, it is checked after
        config.get('bitmessagesettings', 'apiport')
        config.get('bitmessagesettings', 'apiinterface')
        config.get('bitmessagesettings', 'apiusername')
        config.get('bitmessagesettings', 'apipassword')
        print("DEBUG: API configuration found in keys.dat")
    except:  # noqa:E722
        print("DEBUG: API configuration not found in keys.dat, initializing")
        apiInit("")  # Initalize the keys.dat file with API information

    # keys.dat file was found or appropriately configured, allow information retrieval
    # apiEnabled =
    # apiInit(config.safeGetBoolean('bitmessagesettings','apienabled'))
    # #if false it will prompt the user, if true it will return true

    config.read(keysPath)  # read again since changes have been made
    apiPort = int(config.get('bitmessagesettings', 'apiport'))
    apiInterface = config.get('bitmessagesettings', 'apiinterface')
    apiUsername = config.get('bitmessagesettings', 'apiusername')
    apiPassword = config.get('bitmessagesettings', 'apipassword')

    print('\n     API data successfully imported.\n')
    print("DEBUG: API credentials retrieved - Interface:", apiInterface, "Port:", apiPort, "Username:", apiUsername)

    # Build the api credentials
    api_url = "http://" + apiUsername + ":" + apiPassword + "@" + apiInterface + ":" + str(apiPort) + "/"
    print("DEBUG: Constructed API URL:", api_url)
    return api_url

# End keys.dat interactions

def apiTest():
    """Tests the API connection to bitmessage. Returns true if it is connected."""
    print("DEBUG: apiTest() called")
    
    try:
        result = api.add(2, 3)
        print("DEBUG: API test result:", result)
    except Exception as e:  # noqa:E722
        print("DEBUG: API test failed with error:", str(e))
        return False

    return result == 5

def bmSettings():
    """Allows the viewing and modification of keys.dat settings."""
    global keysPath
    global usrPrompt
    print("DEBUG: bmSettings() called")

    keysPath = 'keys.dat'

    config.read(keysPath)  # Read the keys.dat
    try:
        port = config.get('bitmessagesettings', 'port')
        print("DEBUG: Successfully read keys.dat")
    except:  # noqa:E722
        print('\n     File not found.\n')
        usrPrompt = 0
        print("DEBUG: keys.dat not found")
        main()

    startonlogon = config.safeGetBoolean('bitmessagesettings', 'startonlogon')
    minimizetotray = config.safeGetBoolean('bitmessagesettings', 'minimizetotray')
    showtraynotifications = config.safeGetBoolean('bitmessagesettings', 'showtraynotifications')
    startintray = config.safeGetBoolean('bitmessagesettings', 'startintray')
    defaultnoncetrialsperbyte = config.get('bitmessagesettings', 'defaultnoncetrialsperbyte')
    defaultpayloadlengthextrabytes = config.get('bitmessagesettings', 'defaultpayloadlengthextrabytes')
    daemon = config.safeGetBoolean('bitmessagesettings', 'daemon')

    socksproxytype = config.get('bitmessagesettings', 'socksproxytype')
    sockshostname = config.get('bitmessagesettings', 'sockshostname')
    socksport = config.get('bitmessagesettings', 'socksport')
    socksauthentication = config.safeGetBoolean('bitmessagesettings', 'socksauthentication')
    socksusername = config.get('bitmessagesettings', 'socksusername')
    sockspassword = config.get('bitmessagesettings', 'sockspassword')

    print('\n     -----------------------------------')
    print('     |   Current Bitmessage Settings   |')
    print('     -----------------------------------')
    print('     port = ' + port)
    print('     startonlogon = ' + str(startonlogon))
    print('     minimizetotray = ' + str(minimizetotray))
    print('     showtraynotifications = ' + str(showtraynotifications))
    print('     startintray = ' + str(startintray))
    print('     defaultnoncetrialsperbyte = ' + defaultnoncetrialsperbyte)
    print('     defaultpayloadlengthextrabytes = ' + defaultpayloadlengthextrabytes)
    print('     daemon = ' + str(daemon))
    print('\n     ------------------------------------')
    print('     |   Current Connection Settings   |')
    print('     -----------------------------------')
    print('     socksproxytype = ' + socksproxytype)
    print('     sockshostname = ' + sockshostname)
    print('     socksport = ' + socksport)
    print('     socksauthentication = ' + str(socksauthentication))
    print('     socksusername = ' + socksusername)
    print('     sockspassword = ' + sockspassword)
    print(' ')

    uInput = userInput("Would you like to modify any of these settings, (Y)es or (N)o?").lower()
    print("DEBUG: User wants to modify settings:", uInput)

    if uInput == "y":
        while True:  # loops if they mistype the setting name, they can exit the loop with 'exit'
            invalidInput = False
            uInput = userInput("What setting would you like to modify?").lower()
            print(' ')
            print("DEBUG: User wants to modify setting:", uInput)

            if uInput == "port":
                print('     Current port number: ' + port)
                uInput = userInput("Enter the new port number.")
                config.set('bitmessagesettings', 'port', str(uInput))
                print("DEBUG: Changed port to:", uInput)
            elif uInput == "startonlogon":
                print('     Current status: ' + str(startonlogon))
                uInput = userInput("Enter the new status.")
                config.set('bitmessagesettings', 'startonlogon', str(uInput))
                print("DEBUG: Changed startonlogon to:", uInput)
            elif uInput == "minimizetotray":
                print('     Current status: ' + str(minimizetotray))
                uInput = userInput("Enter the new status.")
                config.set('bitmessagesettings', 'minimizetotray', str(uInput))
                print("DEBUG: Changed minimizetotray to:", uInput)
            elif uInput == "showtraynotifications":
                print('     Current status: ' + str(showtraynotifications))
                uInput = userInput("Enter the new status.")
                config.set('bitmessagesettings', 'showtraynotifications', str(uInput))
                print("DEBUG: Changed showtraynotifications to:", uInput)
            elif uInput == "startintray":
                print('     Current status: ' + str(startintray))
                uInput = userInput("Enter the new status.")
                config.set('bitmessagesettings', 'startintray', str(uInput))
                print("DEBUG: Changed startintray to:", uInput)
            elif uInput == "defaultnoncetrialsperbyte":
                print('     Current default nonce trials per byte: ' + defaultnoncetrialsperbyte)
                uInput = userInput("Enter the new defaultnoncetrialsperbyte.")
                config.set('bitmessagesettings', 'defaultnoncetrialsperbyte', str(uInput))
                print("DEBUG: Changed defaultnoncetrialsperbyte to:", uInput)
            elif uInput == "defaultpayloadlengthextrabytes":
                print('     Current default payload length extra bytes: ' + defaultpayloadlengthextrabytes)
                uInput = userInput("Enter the new defaultpayloadlengthextrabytes.")
                config.set('bitmessagesettings', 'defaultpayloadlengthextrabytes', str(uInput))
                print("DEBUG: Changed defaultpayloadlengthextrabytes to:", uInput)
            elif uInput == "daemon":
                print('     Current status: ' + str(daemon))
                uInput = userInput("Enter the new status.").lower()
                config.set('bitmessagesettings', 'daemon', str(uInput))
                print("DEBUG: Changed daemon to:", uInput)
            elif uInput == "socksproxytype":
                print('     Current socks proxy type: ' + socksproxytype)
                print("Possibilities: 'none', 'SOCKS4a', 'SOCKS5'.")
                uInput = userInput("Enter the new socksproxytype.")
                config.set('bitmessagesettings', 'socksproxytype', str(uInput))
                print("DEBUG: Changed socksproxytype to:", uInput)
            elif uInput == "sockshostname":
                print('     Current socks host name: ' + sockshostname)
                uInput = userInput("Enter the new sockshostname.")
                config.set('bitmessagesettings', 'sockshostname', str(uInput))
                print("DEBUG: Changed sockshostname to:", uInput)
            elif uInput == "socksport":
                print('     Current socks port number: ' + socksport)
                uInput = userInput("Enter the new socksport.")
                config.set('bitmessagesettings', 'socksport', str(uInput))
                print("DEBUG: Changed socksport to:", uInput)
            elif uInput == "socksauthentication":
                print('     Current status: ' + str(socksauthentication))
                uInput = userInput("Enter the new status.")
                config.set('bitmessagesettings', 'socksauthentication', str(uInput))
                print("DEBUG: Changed socksauthentication to:", uInput)
            elif uInput == "socksusername":
                print('     Current socks username: ' + socksusername)
                uInput = userInput("Enter the new socksusername.")
                config.set('bitmessagesettings', 'socksusername', str(uInput))
                print("DEBUG: Changed socksusername to:", uInput)
            elif uInput == "sockspassword":
                print('     Current socks password: ' + sockspassword)
                uInput = userInput("Enter the new password.")
                config.set('bitmessagesettings', 'sockspassword', str(uInput))
                print("DEBUG: Changed sockspassword")
            else:
                print("\n     Invalid input. Please try again.\n")
                invalidInput = True
                print("DEBUG: Invalid setting name entered")

            if invalidInput is not True:  # don't prompt if they made a mistake.
                uInput = userInput("Would you like to change another setting, (Y)es or (N)o?").lower()
                print("DEBUG: User wants to change another setting:", uInput)

                if uInput != "y":
                    print('\n     Changes Made.\n')
                    with safe_open(keysPath, 'wb') as configfile:
                        config.write(configfile)
                    restartBmNotify()
                    print("DEBUG: Settings changes saved to keys.dat")
                    break

    elif uInput == "n":
        usrPrompt = 1
        print("DEBUG: User chose not to modify settings")
        main()
    else:
        print("Invalid input.")
        usrPrompt = 1
        print("DEBUG: Invalid user input")
        main()

def validAddress(address):
    """Predicate to test address validity"""
    print("DEBUG: validAddress() called with address:", address)
    try:
        address_information = json.loads(api.decodeAddress(address))
        print("DEBUG: Address validation result:", address_information)
        return 'success' in str(address_information['status']).lower()
    except Exception as e:
        print("DEBUG: Error validating address:", str(e))
        return False

def getAddress(passphrase, vNumber, sNumber):
    """Get a deterministic address"""
    print("DEBUG: getAddress() called with passphrase:", passphrase, "vNumber:", vNumber, "sNumber:", sNumber)
    passphrase = passphrase.encode('base64')  # passphrase must be encoded
    print("DEBUG: Encoded passphrase:", passphrase)

    address = api.getDeterministicAddress(passphrase, vNumber, sNumber)
    print("DEBUG: Generated address:", address)
    return address

def subscribe():
    """Subscribe to an address"""
    global usrPrompt
    print("DEBUG: subscribe() called")

    while True:
        address = userInput("What address would you like to subscribe to?")
        print("DEBUG: User entered address to subscribe:", address)

        if address == "c":
            usrPrompt = 1
            print(' ')
            print("DEBUG: User canceled subscription")
            main()
        elif validAddress(address) is False:
            print('\n     Invalid. "c" to cancel. Please try again.\n')
            print("DEBUG: Invalid address entered")
        else:
            break

    label = userInput("Enter a label for this address.")
    label = label.encode('base64')
    print("DEBUG: Encoded label:", label)

    try:
        result = api.addSubscription(address, label)
        print("DEBUG: Subscription result:", result)
        print('\n     You are now subscribed to: ' + address + '\n')
    except Exception as e:
        print('\n     Error subscribing to address:', str(e), '\n')
        print("DEBUG: Error subscribing:", str(e))

def unsubscribe():
    """Unsusbcribe from an address"""
    global usrPrompt
    print("DEBUG: unsubscribe() called")

    while True:
        address = userInput("What address would you like to unsubscribe from?")
        print("DEBUG: User entered address to unsubscribe:", address)

        if address == "c":
            usrPrompt = 1
            print(' ')
            print("DEBUG: User canceled unsubscription")
            main()
        elif validAddress(address) is False:
            print('\n     Invalid. "c" to cancel. Please try again.\n')
            print("DEBUG: Invalid address entered")
        else:
            break

    uInput = userInput("Are you sure, (Y)es or (N)o?").lower()
    print("DEBUG: User confirmation for unsubscription:", uInput)

    if uInput == "y":
        try:
            result = api.deleteSubscription(address)
            print("DEBUG: Unsubscription result:", result)
            print('\n     You are now unsubscribed from: ' + address + '\n')
        except Exception as e:
            print('\n     Error unsubscribing:', str(e), '\n')
            print("DEBUG: Error unsubscribing:", str(e))
    else:
        print("DEBUG: User canceled unsubscription")

def listSubscriptions():
    """List subscriptions"""
    global usrPrompt
    print("DEBUG: listSubscriptions() called")
    
    print('\nLabel, Address, Enabled\n')
    try:
        subscriptions = api.listSubscriptions()
        print("DEBUG: Subscriptions retrieved:", subscriptions)
        print(subscriptions)
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error listing subscriptions:", str(e))
        usrPrompt = 0
        main()
    print(' ')

def createChan():
    """Create a channel"""
    global usrPrompt
    print("DEBUG: createChan() called")
    
    password = userInput("Enter channel name")
    password = password.encode('base64')
    print("DEBUG: Encoded channel password:", password)
    
    try:
        result = api.createChan(password)
        print("DEBUG: Channel creation result:", result)
        print(result)
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error creating channel:", str(e))
        usrPrompt = 0
        main()

def joinChan():
    """Join a channel"""
    global usrPrompt
    print("DEBUG: joinChan() called")
    
    while True:
        address = userInput("Enter channel address")
        print("DEBUG: User entered channel address:", address)

        if address == "c":
            usrPrompt = 1
            print(' ')
            print("DEBUG: User canceled channel join")
            main()
        elif validAddress(address) is False:
            print('\n     Invalid. "c" to cancel. Please try again.\n')
            print("DEBUG: Invalid channel address")
        else:
            break

    password = userInput("Enter channel name")
    password = password.encode('base64')
    print("DEBUG: Encoded channel password:", password)
    
    try:
        result = api.joinChan(password, address)
        print("DEBUG: Channel join result:", result)
        print(result)
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error joining channel:", str(e))
        usrPrompt = 0
        main()

def leaveChan():
    """Leave a channel"""
    global usrPrompt
    print("DEBUG: leaveChan() called")
    
    while True:
        address = userInput("Enter channel address")
        print("DEBUG: User entered channel address:", address)

        if address == "c":
            usrPrompt = 1
            print(' ')
            print("DEBUG: User canceled channel leave")
            main()
        elif validAddress(address) is False:
            print('\n     Invalid. "c" to cancel. Please try again.\n')
            print("DEBUG: Invalid channel address")
        else:
            break

    try:
        result = api.leaveChan(address)
        print("DEBUG: Channel leave result:", result)
        print(result)
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error leaving channel:", str(e))
        usrPrompt = 0
        main()

def listAdd():
    """List all of the addresses and their info"""
    global usrPrompt
    print("DEBUG: listAdd() called")
    
    try:
        jsonAddresses = json.loads(api.listAddresses())
        numAddresses = len(jsonAddresses['addresses'])  # Number of addresses
        print("DEBUG: Retrieved", numAddresses, "addresses")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error listing addresses:", str(e))
        usrPrompt = 0
        main()

    # print('\nAddress Number,Label,Address,Stream,Enabled\n')
    print('\n     --------------------------------------------------------------------------')
    print('     | # |       Label       |               Address               |S#|Enabled|')
    print('     |---|-------------------|-------------------------------------|--|-------|')
    for addNum in range(0, numAddresses):  # processes all of the addresses and lists them out
        label = (jsonAddresses['addresses'][addNum]['label']).encode(
            'utf')  # may still misdiplay in some consoles
        address = str(jsonAddresses['addresses'][addNum]['address'])
        stream = str(jsonAddresses['addresses'][addNum]['stream'])
        enabled = str(jsonAddresses['addresses'][addNum]['enabled'])

        if len(label) > 19:
            label = label[:16] + '...'

        print(''.join([
            '     |',
            str(addNum).ljust(3),
            '|',
            label.ljust(19),
            '|',
            address.ljust(37),
            '|',
            stream.ljust(1),
            '|',
            enabled.ljust(7),
            '|',
        ]))

    print(''.join([
        '     ',
        74 * '-',
        '\n',
    ]))
    print("DEBUG: Finished listing addresses")

def genAdd(lbl, deterministic, passphrase, numOfAdd, addVNum, streamNum, ripe):
    """Generate address"""
    global usrPrompt
    print("DEBUG: genAdd() called with parameters:", {
        'lbl': lbl, 
        'deterministic': deterministic,
        'passphrase': passphrase,
        'numOfAdd': numOfAdd,
        'addVNum': addVNum,
        'streamNum': streamNum,
        'ripe': ripe
    })

    if deterministic is False:  # Generates a new address with the user defined label. non-deterministic
        addressLabel = lbl.encode('base64')
        print("DEBUG: Encoded address label:", addressLabel)
        try:
            generatedAddress = api.createRandomAddress(addressLabel)
            print("DEBUG: Generated random address:", generatedAddress)
            return generatedAddress
        except Exception as e:  # noqa:E722
            print('\n     Connection Error\n')
            print("DEBUG: Error generating random address:", str(e))
            usrPrompt = 0
            main()

    elif deterministic:  # Generates a new deterministic address with the user inputs.
        passphrase = passphrase.encode('base64')
        print("DEBUG: Encoded passphrase:", passphrase)
        try:
            generatedAddress = api.createDeterministicAddresses(passphrase, numOfAdd, addVNum, streamNum, ripe)
            print("DEBUG: Generated deterministic address:", generatedAddress)
            return generatedAddress
        except Exception as e:  # noqa:E722
            print('\n     Connection Error\n')
            print("DEBUG: Error generating deterministic address:", str(e))
            usrPrompt = 0
            main()

    print("DEBUG: Invalid parameters for address generation")
    return 'Entry Error'

def saveFile(fileName, fileData):
    """Allows attachments and messages/broadcats to be saved"""
    print("DEBUG: saveFile() called with filename:", fileName)
    
    # This section finds all invalid characters and replaces them with ~
    fileName = fileName.replace(" ", "")
    fileName = fileName.replace("/", "~")
    # fileName = fileName.replace("\\", "~") How do I get this to work...?
    fileName = fileName.replace(":", "~")
    fileName = fileName.replace("*", "~")
    fileName = fileName.replace("?", "~")
    fileName = fileName.replace('"', "~")
    fileName = fileName.replace("<", "~")
    fileName = fileName.replace(">", "~")
    fileName = fileName.replace("|", "~")
    print("DEBUG: Sanitized filename:", fileName)

    directory = os.path.abspath('attachments')
    print("DEBUG: Attachment directory:", directory)

    if not os.path.exists(directory):
        os.makedirs(directory)
        print("DEBUG: Created attachments directory")

    filePath = os.path.join(directory, fileName)
    print("DEBUG: Full file path:", filePath)

    try:
        with safe_open(filePath, 'wb+') as path_to_file:
            path_to_file.write(fileData.decode("base64"))
        print('\n     Successfully saved ' + filePath + '\n')
        print("DEBUG: File saved successfully")
    except Exception as e:
        print('\n     Error saving file:', str(e), '\n')
        print("DEBUG: Error saving file:", str(e))

def attachment():
    """Allows users to attach a file to their message or broadcast"""
    print("DEBUG: attachment() called")
    
    theAttachmentS = ''

    while True:
        isImage = False
        theAttachment = ''

        while True:  # loops until valid path is entered
            filePath = userInput(
                '\nPlease enter the path to the attachment or just the attachment name if in this folder.')
            print("DEBUG: User entered file path:", filePath)

            try:
                with safe_open(filePath):
                    print("DEBUG: File found at path:", filePath)
                    break
            except IOError:
                print('\n     %s was not found on your filesystem or can not be opened.\n' % filePath)
                print("DEBUG: File not found or inaccessible:", filePath)

        # print(filesize, and encoding estimate with confirmation if file is over X size(1mb?))
        invSize = os.path.getsize(filePath)
        invSize = (invSize / 1024)  # Converts to kilobytes
        round(invSize, 2)  # Rounds to two decimal places
        print("DEBUG: File size:", invSize, "KB")

        if invSize > 500.0:  # If over 500KB
            print(''.join([
                '\n     WARNING:The file that you are trying to attach is ',
                str(invSize),
                'KB and will take considerable time to send.\n'
            ]))
            uInput = userInput('Are you sure you still want to attach it, (Y)es or (N)o?').lower()
            print("DEBUG: User confirmation for large file:", uInput)

            if uInput != "y":
                print('\n     Attachment discarded.\n')
                print("DEBUG: User canceled large file attachment")
                return ''
        elif invSize > 184320.0:  # If larger than 180MB, discard.
            print('\n     Attachment too big, maximum allowed size:180MB\n')
            print("DEBUG: File too large, discarding")
            main()

        pathLen = len(str(ntpath.basename(filePath)))  # Gets the length of the filepath excluding the filename
        fileName = filePath[(len(str(filePath)) - pathLen):]  # reads the filename
        print("DEBUG: Extracted filename:", fileName)

        filetype = imghdr.what(filePath)  # Tests if it is an image file
        if filetype is not None:
            print('\n     ---------------------------------------------------')
            print('     Attachment detected as an Image.')
            print('     <img> tags will automatically be included,')
            print('     allowing the recipient to view the image')
            print('     using the "View HTML code..." option in Bitmessage.')
            print('     ---------------------------------------------------\n')
            isImage = True
            print("DEBUG: Detected image file type:", filetype)
            time.sleep(2)

        # Alert the user that the encoding process may take some time.
        print('\n     Encoding Attachment, Please Wait ...\n')

        with safe_open(filePath, 'rb') as f:  # Begin the actual encoding
            data = f.read(188743680)  # Reads files up to 180MB, the maximum size for Bitmessage.
            data = data.encode("base64")
        print("DEBUG: File encoded to base64")

        if isImage:  # If it is an image, include image tags in the message
            theAttachment = """
<!-- Note: Image attachment below. Please use the right click "View HTML code ..." option to view it. -->
<!-- Sent using Bitmessage Daemon. https://github.com/Dokument/PyBitmessage-Daemon -->

Filename:%s
Filesize:%sKB
Encoding:base64

<center>
    <div id="image">
        <img alt = "%s" src='data:image/%s;base64, %s' />
    </div>
</center>""" % (fileName, invSize, fileName, filetype, data)
            print("DEBUG: Created image attachment HTML")
        else:  # Else it is not an image so do not include the embedded image code.
            theAttachment = """
<!-- Note: File attachment below. Please use a base64 decoder, or Daemon, to save it. -->
<!-- Sent using Bitmessage Daemon. https://github.com/Dokument/PyBitmessage-Daemon -->

Filename:%s
Filesize:%sKB
Encoding:base64

<attachment alt = "%s" src='data:file/%s;base64, %s' />""" % (fileName, invSize, fileName, fileName, data)
            print("DEBUG: Created file attachment HTML")

        uInput = userInput('Would you like to add another attachment, (Y)es or (N)o?').lower()
        print("DEBUG: User wants to add another attachment:", uInput)

        if uInput in ('y', 'yes'):  # Allows multiple attachments to be added to one message
            theAttachmentS = str(theAttachmentS) + str(theAttachment) + '\n\n'
            print("DEBUG: Added attachment to collection")
        elif uInput in ('n', 'no'):
            print("DEBUG: User finished adding attachments")
            break

    theAttachmentS = theAttachmentS + theAttachment
    print("DEBUG: Final attachment content length:", len(theAttachmentS))
    return theAttachmentS

def sendMsg(toAddress, fromAddress, subject, message):
    """
    With no arguments sent, sendMsg fills in the blanks.
    subject and message must be encoded before they are passed.
    """
    global usrPrompt
    print("DEBUG: sendMsg() called with parameters:", {
        'toAddress': toAddress,
        'fromAddress': fromAddress,
        'subject': subject,
        'message': message[:100] + '...' if message and len(message) > 100 else message
    })

    if validAddress(toAddress) is False:
        while True:
            toAddress = userInput("What is the To Address?")
            print("DEBUG: User entered toAddress:", toAddress)

            if toAddress == "c":
                usrPrompt = 1
                print(' ')
                print("DEBUG: User canceled message sending")
                main()
            elif validAddress(toAddress) is False:
                print('\n     Invalid Address. "c" to cancel. Please try again.\n')
                print("DEBUG: Invalid toAddress entered")
            else:
                break

    if validAddress(fromAddress) is False:
        try:
            jsonAddresses = json.loads(api.listAddresses())
            numAddresses = len(jsonAddresses['addresses'])  # Number of addresses
            print("DEBUG: Found", numAddresses, "available addresses")
        except Exception as e:  # noqa:E722
            print('\n     Connection Error\n')
            print("DEBUG: Error listing addresses:", str(e))
            usrPrompt = 0
            main()

        if numAddresses > 1:  # Ask what address to send from if multiple addresses
            found = False
            while True:
                print(' ')
                fromAddress = userInput("Enter an Address or Address Label to send from.")
                print("DEBUG: User entered fromAddress:", fromAddress)

                if fromAddress == "exit":
                    usrPrompt = 1
                    print("DEBUG: User canceled message sending")
                    main()

                for addNum in range(0, numAddresses):  # processes all of the addresses
                    label = jsonAddresses['addresses'][addNum]['label']
                    address = jsonAddresses['addresses'][addNum]['address']
                    if fromAddress == label:  # address entered was a label and is found
                        fromAddress = address
                        found = True
                        print("DEBUG: Found matching label, using address:", fromAddress)
                        break

                if found is False:
                    if validAddress(fromAddress) is False:
                        print('\n     Invalid Address. Please try again.\n')
                        print("DEBUG: Invalid fromAddress entered")

                    else:
                        for addNum in range(0, numAddresses):  # processes all of the addresses
                            address = jsonAddresses['addresses'][addNum]['address']
                            if fromAddress == address:  # address entered was a found in our addressbook.
                                found = True
                                print("DEBUG: Found matching address in addressbook")
                                break

                        if found is False:
                            print('\n     The address entered is not one of yours. Please try again.\n')
                            print("DEBUG: Address not found in addressbook")

                if found:
                    break  # Address was found

        else:  # Only one address in address book
            print('\n     Using the only address in the addressbook to send from.\n')
            fromAddress = jsonAddresses['addresses'][0]['address']
            print("DEBUG: Using only available address:", fromAddress)

    if not subject:
        subject = userInput("Enter your Subject.")
        subject = subject.encode('base64')
        print("DEBUG: Encoded subject:", subject)
    if not message:
        message = userInput("Enter your Message.")

        uInput = userInput('Would you like to add an attachment, (Y)es or (N)o?').lower()
        print("DEBUG: User wants to add attachment:", uInput)
        if uInput == "y":
            attachment_content = attachment()
            message = message + '\n\n' + attachment_content
            print("DEBUG: Added attachment to message")

        message = message.encode('base64')
        print("DEBUG: Encoded message")

    try:
        ackData = api.sendMessage(toAddress, fromAddress, subject, message)
        status = api.getStatus(ackData)
        print('\n     Message Status:', status, '\n')
        print("DEBUG: Message sent successfully, status:", status)
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error sending message:", str(e))
        usrPrompt = 0
        main()

def sendBrd(fromAddress, subject, message):
    """Send a broadcast"""
    global usrPrompt
    print("DEBUG: sendBrd() called with parameters:", {
        'fromAddress': fromAddress,
        'subject': subject,
        'message': message[:100] + '...' if message and len(message) > 100 else message
    })

    if not fromAddress:
        try:
            jsonAddresses = json.loads(api.listAddresses())
            numAddresses = len(jsonAddresses['addresses'])  # Number of addresses
            print("DEBUG: Found", numAddresses, "available addresses")
        except Exception as e:  # noqa:E722
            print('\n     Connection Error\n')
            print("DEBUG: Error listing addresses:", str(e))
            usrPrompt = 0
            main()

        if numAddresses > 1:  # Ask what address to send from if multiple addresses
            found = False
            while True:
                fromAddress = userInput("\nEnter an Address or Address Label to send from.")
                print("DEBUG: User entered fromAddress:", fromAddress)

                if fromAddress == "exit":
                    usrPrompt = 1
                    print("DEBUG: User canceled broadcast sending")
                    main()

                for addNum in range(0, numAddresses):  # processes all of the addresses
                    label = jsonAddresses['addresses'][addNum]['label']
                    address = jsonAddresses['addresses'][addNum]['address']
                    if fromAddress == label:  # address entered was a label and is found
                        fromAddress = address
                        found = True
                        print("DEBUG: Found matching label, using address:", fromAddress)
                        break

                if found is False:
                    if validAddress(fromAddress) is False:
                        print('\n     Invalid Address. Please try again.\n')
                        print("DEBUG: Invalid fromAddress entered")

                    else:
                        for addNum in range(0, numAddresses):  # processes all of the addresses
                            address = jsonAddresses['addresses'][addNum]['address']
                            if fromAddress == address:  # address entered was a found in our addressbook.
                                found = True
                                print("DEBUG: Found matching address in addressbook")
                                break

                        if found is False:
                            print('\n     The address entered is not one of yours. Please try again.\n')
                            print("DEBUG: Address not found in addressbook")

                if found:
                    break  # Address was found

        else:  # Only one address in address book
            print('\n     Using the only address in the addressbook to send from.\n')
            fromAddress = jsonAddresses['addresses'][0]['address']
            print("DEBUG: Using only available address:", fromAddress)

    if not subject:
        subject = userInput("Enter your Subject.")
        subject = subject.encode('base64')
        print("DEBUG: Encoded subject:", subject)
    if not message:
        message = userInput("Enter your Message.")

        uInput = userInput('Would you like to add an attachment, (Y)es or (N)o?').lower()
        print("DEBUG: User wants to add attachment:", uInput)
        if uInput == "y":
            attachment_content = attachment()
            message = message + '\n\n' + attachment_content
            print("DEBUG: Added attachment to message")

        message = message.encode('base64')
        print("DEBUG: Encoded message")

    try:
        ackData = api.sendBroadcast(fromAddress, subject, message)
        status = api.getStatus(ackData)
        print('\n     Message Status:', status, '\n')
        print("DEBUG: Broadcast sent successfully, status:", status)
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error sending broadcast:", str(e))
        usrPrompt = 0
        main()

def inbox(unreadOnly=False):
    """Lists the messages by: Message Number, To Address Label, From Address Label, Subject, Received Time)"""
    global usrPrompt
    print("DEBUG: inbox() called with unreadOnly:", unreadOnly)
    
    try:
        inboxMessages = json.loads(api.getAllInboxMessages())
        numMessages = len(inboxMessages['inboxMessages'])
        print("DEBUG: Found", numMessages, "inbox messages")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error retrieving inbox messages:", str(e))
        usrPrompt = 0
        main()

    messagesPrinted = 0
    messagesUnread = 0
    for msgNum in range(0, numMessages):  # processes all of the messages in the inbox
        message = inboxMessages['inboxMessages'][msgNum]
        # if we are displaying all messages or if this message is unread then display it
        if not unreadOnly or not message['read']:
            print('     -----------------------------------\n')
            print('     Message Number:', msgNum)  # Message Number)
            print('     To:', getLabelForAddress(message['toAddress']))  # Get the to address)
            print('     From:', getLabelForAddress(message['fromAddress']))  # Get the from address)
            print('     Subject:', message['subject'].decode('base64'))  # Get the subject)
            print(''.join([
                '     Received:',
                datetime.datetime.fromtimestamp(
                    float(message['receivedTime'])).strftime('%Y-%m-%d %H:%M:%S'),
            ]))
            messagesPrinted += 1
            if not message['read']:
                messagesUnread += 1

        if messagesPrinted % 20 == 0 and messagesPrinted != 0:
            uInput = userInput('(Press Enter to continue or type (Exit) to return to the main menu.)').lower()
            print("DEBUG: User pagination input:", uInput)
            if uInput == 'exit':
                break

    print('\n     -----------------------------------')
    print('     There are %d unread messages of %d messages in the inbox.' % (messagesUnread, numMessages))
    print('     -----------------------------------\n')
    print("DEBUG: Finished displaying inbox")

def outbox():
    """TBC"""
    global usrPrompt
    print("DEBUG: outbox() called")
    
    try:
        outboxMessages = json.loads(api.getAllSentMessages())
        numMessages = len(outboxMessages['sentMessages'])
        print("DEBUG: Found", numMessages, "sent messages")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error retrieving sent messages:", str(e))
        usrPrompt = 0
        main()

    for msgNum in range(0, numMessages):  # processes all of the messages in the outbox
        print('\n     -----------------------------------\n')
        print('     Message Number:', msgNum)  # Message Number)
        # print('     Message ID:', outboxMessages['sentMessages'][msgNum]['msgid'])
        print('     To:', getLabelForAddress(
            outboxMessages['sentMessages'][msgNum]['toAddress']
        ))  # Get the to address)
        # Get the from address
        print('     From:', getLabelForAddress(outboxMessages['sentMessages'][msgNum]['fromAddress']))
        print('     Subject:', outboxMessages['sentMessages'][msgNum]['subject'].decode('base64'))  # Get the subject)
        print('     Status:', outboxMessages['sentMessages'][msgNum]['status'])  # Get the subject)

        # print(''.join([
        #     '     Last Action Time:',
        #     datetime.datetime.fromtimestamp(
        #         float(outboxMessages['sentMessages'][msgNum]['lastActionTime'])).strftime('%Y-%m-%d %H:%M:%S'),
        # ]))
        print(''.join([
            '     Last Action Time:',
            datetime.datetime.fromtimestamp(
                float(outboxMessages['sentMessages'][msgNum]['lastActionTime'])).strftime('%Y-%m-%d %H:%M:%S'),
        ]))

        if msgNum % 20 == 0 and msgNum != 0:
            uInput = userInput('(Press Enter to continue or type (Exit) to return to the main menu.)').lower()
            print("DEBUG: User pagination input:", uInput)
            if uInput == 'exit':
                break

    print('\n     -----------------------------------')
    print('     There are ', numMessages, ' messages in the outbox.')
    print('     -----------------------------------\n')
    print("DEBUG: Finished displaying outbox")

def readSentMsg(msgNum):
    """Opens a sent message for reading"""
    global usrPrompt
    print("DEBUG: readSentMsg() called with msgNum:", msgNum)
    
    try:
        outboxMessages = json.loads(api.getAllSentMessages())
        numMessages = len(outboxMessages['sentMessages'])
        print("DEBUG: Found", numMessages, "sent messages")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error retrieving sent messages:", str(e))
        usrPrompt = 0
        main()

    print(' ')

    if msgNum >= numMessages:
        print('\n     Invalid Message Number.\n')
        print("DEBUG: Invalid message number:", msgNum)
        main()

    # Begin attachment detection
    message = outboxMessages['sentMessages'][msgNum]['message'].decode('base64')
    print("DEBUG: Decoded message content")

    while True:  # Allows multiple messages to be downloaded/saved
        if ';base64,' in message:  # Found this text in the message, there is probably an attachment.
            attPos = message.index(";base64,")  # Finds the attachment position
            attEndPos = message.index("' />")  # Finds the end of the attachment
            # attLen = attEndPos - attPos #Finds the length of the message

            if 'alt = "' in message:  # We can get the filename too
                fnPos = message.index('alt = "')  # Finds position of the filename
                fnEndPos = message.index('" src=')  # Finds the end position
                # fnLen = fnEndPos - fnPos #Finds the length of the filename

                fileName = message[fnPos + 7:fnEndPos]
            else:
                fnPos = attPos
                fileName = 'Attachment'

            uInput = userInput(
                '\n     Attachment Detected. Would you like to save the attachment, (Y)es or (N)o?').lower()
            print("DEBUG: User wants to save attachment:", uInput)
            if uInput in ("y", 'yes'):

                this_attachment = message[attPos + 9:attEndPos]
                saveFile(fileName, this_attachment)

            message = message[:fnPos] + '~<Attachment data removed for easier viewing>~' + message[(attEndPos + 4):]

        else:
            break

    # End attachment Detection

    print('\n     To:', getLabelForAddress(outboxMessages['sentMessages'][msgNum]['toAddress']))  # Get the to address)
    # Get the from address
    print('     From:', getLabelForAddress(outboxMessages['sentMessages'][msgNum]['fromAddress']))
    print('     Subject:', outboxMessages['sentMessages'][msgNum]['subject'].decode('base64'))  # Get the subject)
    print('     Status:', outboxMessages['sentMessages'][msgNum]['status'])  # Get the subject)
    print(''.join([
        '     Last Action Time:',
        datetime.datetime.fromtimestamp(
            float(outboxMessages['sentMessages'][msgNum]['lastActionTime'])).strftime('%Y-%m-%d %H:%M:%S'),
    ]))
    print('     Message:\n')
    print(message)  # inboxMessages['inboxMessages'][msgNum]['message'].decode('base64'))
    print(' ')
    print("DEBUG: Finished displaying sent message")

def readMsg(msgNum):
    """Open a message for reading"""
    global usrPrompt
    print("DEBUG: readMsg() called with msgNum:", msgNum)
    
    try:
        inboxMessages = json.loads(api.getAllInboxMessages())
        numMessages = len(inboxMessages['inboxMessages'])
        print("DEBUG: Found", numMessages, "inbox messages")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error retrieving inbox messages:", str(e))
        usrPrompt = 0
        main()

    if msgNum >= numMessages:
        print('\n     Invalid Message Number.\n')
        print("DEBUG: Invalid message number:", msgNum)
        main()

    # Begin attachment detection
    message = inboxMessages['inboxMessages'][msgNum]['message'].decode('base64')
    print("DEBUG: Decoded message content")

    while True:  # Allows multiple messages to be downloaded/saved
        if ';base64,' in message:  # Found this text in the message, there is probably an attachment.
            attPos = message.index(";base64,")  # Finds the attachment position
            attEndPos = message.index("' />")  # Finds the end of the attachment
            # attLen = attEndPos - attPos #Finds the length of the message

            if 'alt = "' in message:  # We can get the filename too
                fnPos = message.index('alt = "')  # Finds position of the filename
                fnEndPos = message.index('" src=')  # Finds the end position
                # fnLen = fnEndPos - fnPos #Finds the length of the filename

                fileName = message[fnPos + 7:fnEndPos]
            else:
                fnPos = attPos
                fileName = 'Attachment'

            uInput = userInput(
                '\n     Attachment Detected. Would you like to save the attachment, (Y)es or (N)o?').lower()
            print("DEBUG: User wants to save attachment:", uInput)
            if uInput in ("y", 'yes'):

                this_attachment = message[attPos + 9:attEndPos]
                saveFile(fileName, this_attachment)

            message = message[:fnPos] + '~<Attachment data removed for easier viewing>~' + message[attEndPos + 4:]

        else:
            break

    # End attachment Detection
    print('\n     To:', getLabelForAddress(inboxMessages['inboxMessages'][msgNum]['toAddress']))  # Get the to address)
    # Get the from address
    print('     From:', getLabelForAddress(inboxMessages['inboxMessages'][msgNum]['fromAddress']))
    print('     Subject:', inboxMessages['inboxMessages'][msgNum]['subject'].decode('base64'))  # Get the subject)
    print(''.join([
        '     Received:', datetime.datetime.fromtimestamp(
            float(inboxMessages['inboxMessages'][msgNum]['receivedTime'])).strftime('%Y-%m-%d %H:%M:%S'),
    ]))
    print('     Message:\n')
    print(message)  # inboxMessages['inboxMessages'][msgNum]['message'].decode('base64'))
    print(' ')
    
    messageID = inboxMessages['inboxMessages'][msgNum]['msgid']
    print("DEBUG: Finished displaying message, returning message ID:", messageID)
    return messageID

def replyMsg(msgNum, forwardORreply):
    """Allows you to reply to the message you are currently on. Saves typing in the addresses and subject."""
    global usrPrompt
    print("DEBUG: replyMsg() called with msgNum:", msgNum, "forwardORreply:", forwardORreply)
    
    forwardORreply = forwardORreply.lower()  # makes it lowercase
    try:
        inboxMessages = json.loads(api.getAllInboxMessages())
        print("DEBUG: Retrieved inbox messages")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error retrieving inbox messages:", str(e))
        usrPrompt = 0
        main()

    fromAdd = inboxMessages['inboxMessages'][msgNum]['toAddress']  # Address it was sent To, now the From address
    message = inboxMessages['inboxMessages'][msgNum]['message'].decode('base64')  # Message that you are replying too.
    print("DEBUG: Original message content:", message[:100] + '...' if len(message) > 100 else message)

    subject = inboxMessages['inboxMessages'][msgNum]['subject']
    subject = subject.decode('base64')
    print("DEBUG: Original subject:", subject)

    if forwardORreply == 'reply':
        toAdd = inboxMessages['inboxMessages'][msgNum]['fromAddress']  # Address it was From, now the To address
        subject = "Re: " + subject
        print("DEBUG: Replying to address:", toAdd)
    elif forwardORreply == 'forward':
        subject = "Fwd: " + subject
        print("DEBUG: Forwarding message")

        while True:
            toAdd = userInput("What is the To Address?")
            print("DEBUG: User entered forward to address:", toAdd)

            if toAdd == "c":
                usrPrompt = 1
                print(' ')
                print("DEBUG: User canceled forwarding")
                main()
            elif validAddress(toAdd) is False:
                print('\n     Invalid Address. "c" to cancel. Please try again.\n')
                print("DEBUG: Invalid forward to address")
            else:
                break
    else:
        print('\n     Invalid Selection. Reply or Forward only')
        print("DEBUG: Invalid reply/forward option")
        usrPrompt = 0
        main()

    subject = subject.encode('base64')
    print("DEBUG: Encoded subject:", subject)

    newMessage = userInput("Enter your Message.")
    print("DEBUG: User entered new message content")

    uInput = userInput('Would you like to add an attachment, (Y)es or (N)o?').lower()
    print("DEBUG: User wants to add attachment:", uInput)
    if uInput == "y":
        attachment_content = attachment()
        newMessage = newMessage + '\n\n' + attachment_content
        print("DEBUG: Added attachment to reply")

    newMessage = newMessage + '\n\n------------------------------------------------------\n'
    newMessage = newMessage + message
    newMessage = newMessage.encode('base64')
    print("DEBUG: Encoded new message")

    sendMsg(toAdd, fromAdd, subject, newMessage)
    print("DEBUG: Reply/forward message sent")

    main()

def delMsg(msgNum):
    """Deletes a specified message from the inbox"""
    global usrPrompt
    print("DEBUG: delMsg() called with msgNum:", msgNum)
    
    try:
        inboxMessages = json.loads(api.getAllInboxMessages())
        # gets the message ID via the message index number
        msgId = inboxMessages['inboxMessages'][int(msgNum)]['msgid']
        print("DEBUG: Found message ID to delete:", msgId)

        msgAck = api.trashMessage(msgId)
        print("DEBUG: Message deletion result:", msgAck)
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error deleting message:", str(e))
        usrPrompt = 0
        main()

    return msgAck

def delSentMsg(msgNum):
    """Deletes a specified message from the outbox"""
    global usrPrompt
    print("DEBUG: delSentMsg() called with msgNum:", msgNum)
    
    try:
        outboxMessages = json.loads(api.getAllSentMessages())
        # gets the message ID via the message index number
        msgId = outboxMessages['sentMessages'][int(msgNum)]['msgid']
        print("DEBUG: Found sent message ID to delete:", msgId)
        
        msgAck = api.trashSentMessage(msgId)
        print("DEBUG: Sent message deletion result:", msgAck)
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error deleting sent message:", str(e))
        usrPrompt = 0
        main()

    return msgAck

def getLabelForAddress(address):
    """Get label for an address"""
    print("DEBUG: getLabelForAddress() called with address:", address)
    
    if address in knownAddresses:
        print("DEBUG: Found address in knownAddresses")
        return knownAddresses[address]
    else:
        print("DEBUG: Address not in knownAddresses, building cache")
        buildKnownAddresses()
        if address in knownAddresses:
            print("DEBUG: Found address in knownAddresses after building cache")
            return knownAddresses[address]

    print("DEBUG: Address not found, returning raw address")
    return address

def buildKnownAddresses():
    """Build known addresses"""
    global usrPrompt
    print("DEBUG: buildKnownAddresses() called")

    # add from address book
    try:
        response = api.listAddressBookEntries()
        # if api is too old then fail
        if "API Error 0020" in response:
            print("DEBUG: API too old for listAddressBookEntries")
            return
        addressBook = json.loads(response)
        print("DEBUG: Retrieved address book entries")
        for entry in addressBook['addresses']:
            if entry['address'] not in knownAddresses:
                knownAddresses[entry['address']] = "%s (%s)" % (entry['label'].decode('base64'), entry['address'])
                print("DEBUG: Added address to knownAddresses:", entry['address'])
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error building known addresses from address book:", str(e))
        usrPrompt = 0
        main()

    # add from my addresses
    try:
        response = api.listAddresses2()
        # if api is too old just return then fail
        if "API Error 0020" in response:
            print("DEBUG: API too old for listAddresses2")
            return
        addresses = json.loads(response)
        print("DEBUG: Retrieved own addresses")
        for entry in addresses['addresses']:
            if entry['address'] not in knownAddresses:
                knownAddresses[entry['address']] = "%s (%s)" % (entry['label'].decode('base64'), entry['address'])
                print("DEBUG: Added own address to knownAddresses:", entry['address'])
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error building known addresses from own addresses:", str(e))
        usrPrompt = 0
        main()

def listAddressBookEntries():
    """List addressbook entries"""
    global usrPrompt
    print("DEBUG: listAddressBookEntries() called")

    try:
        response = api.listAddressBookEntries()
        if "API Error" in response:
            print("DEBUG: API error in listAddressBookEntries:", response)
            return getAPIErrorCode(response)
        addressBook = json.loads(response)
        print('     --------------------------------------------------------------')
        print('     |        Label       |                Address                |')
        print('     |--------------------|---------------------------------------|')
        for entry in addressBook['addresses']:
            label = entry['label'].decode('base64')
            address = entry['address']
            if len(label) > 19:
                label = label[:16] + '...'
            print('     | ' + label.ljust(19) + '| ' + address.ljust(37) + ' |')
        print('     --------------------------------------------------------------')
        print("DEBUG: Displayed address book entries")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error listing address book entries:", str(e))
        usrPrompt = 0
        main()

def addAddressToAddressBook(address, label):
    """Add an address to an addressbook"""
    global usrPrompt
    print("DEBUG: addAddressToAddressBook() called with address:", address, "label:", label)

    try:
        response = api.addAddressBookEntry(address, label.encode('base64'))
        if "API Error" in response:
            print("DEBUG: API error in addAddressBookEntry:", response)
            return getAPIErrorCode(response)
        print("DEBUG: Added address to address book")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error adding address to address book:", str(e))
        usrPrompt = 0
        main()

def deleteAddressFromAddressBook(address):
    """Delete an address from an addressbook"""
    global usrPrompt
    print("DEBUG: deleteAddressFromAddressBook() called with address:", address)

    try:
        response = api.deleteAddressBookEntry(address)
        if "API Error" in response:
            print("DEBUG: API error in deleteAddressBookEntry:", response)
            return getAPIErrorCode(response)
        print("DEBUG: Deleted address from address book")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error deleting address from address book:", str(e))
        usrPrompt = 0
        main()

def getAPIErrorCode(response):
    """Get API error code"""
    print("DEBUG: getAPIErrorCode() called with response:", response)
    
    if "API Error" in response:
        # if we got an API error return the number by getting the number
        # after the second space and removing the trailing colon
        error_code = int(response.split()[2][:-1])
        print("DEBUG: Extracted API error code:", error_code)
        return error_code

def markMessageRead(messageID):
    """Mark a message as read"""
    global usrPrompt
    print("DEBUG: markMessageRead() called with messageID:", messageID)

    try:
        response = api.getInboxMessageByID(messageID, True)
        if "API Error" in response:
            print("DEBUG: API error in markMessageRead:", response)
            return getAPIErrorCode(response)
        print("DEBUG: Marked message as read")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error marking message as read:", str(e))
        usrPrompt = 0
        main()

def markMessageUnread(messageID):
    """Mark a mesasge as unread"""
    global usrPrompt
    print("DEBUG: markMessageUnread() called with messageID:", messageID)

    try:
        response = api.getInboxMessageByID(messageID, False)
        if "API Error" in response:
            print("DEBUG: API error in markMessageUnread:", response)
            return getAPIErrorCode(response)
        print("DEBUG: Marked message as unread")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error marking message as unread:", str(e))
        usrPrompt = 0
        main()

def markAllMessagesRead():
    """Mark all messages as read"""
    global usrPrompt
    print("DEBUG: markAllMessagesRead() called")

    try:
        inboxMessages = json.loads(api.getAllInboxMessages())['inboxMessages']
        print("DEBUG: Retrieved all inbox messages for marking as read")
        for message in inboxMessages:
            if not message['read']:
                markMessageRead(message['msgid'])
        print("DEBUG: Marked all unread messages as read")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error marking all messages as read:", str(e))
        usrPrompt = 0
        main()

def markAllMessagesUnread():
    """Mark all messages as unread"""
    global usrPrompt
    print("DEBUG: markAllMessagesUnread() called")

    try:
        inboxMessages = json.loads(api.getAllInboxMessages())['inboxMessages']
        print("DEBUG: Retrieved all inbox messages for marking as unread")
        for message in inboxMessages:
            if message['read']:
                markMessageUnread(message['msgid'])
        print("DEBUG: Marked all read messages as unread")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error marking all messages as unread:", str(e))
        usrPrompt = 0
        main()

def clientStatus():
    """Print (the client status"""
    global usrPrompt
    print("DEBUG: clientStatus() called")

    try:
        client_status = json.loads(api.clientStatus())
        print("DEBUG: Retrieved client status")
    except Exception as e:  # noqa:E722
        print('\n     Connection Error\n')
        print("DEBUG: Error retrieving client status:", str(e))
        usrPrompt = 0
        main()

    print("\nnetworkStatus: " + client_status['networkStatus'] + "\n")
    print("\nnetworkConnections: " + str(client_status['networkConnections']) + "\n")
    print("\nnumberOfPubkeysProcessed: " + str(client_status['numberOfPubkeysProcessed']) + "\n")
    print("\nnumberOfMessagesProcessed: " + str(client_status['numberOfMessagesProcessed']) + "\n")
    print("\nnumberOfBroadcastsProcessed: " + str(client_status['numberOfBroadcastsProcessed']) + "\n")
    print("DEBUG: Displayed client status")

def shutdown():
    """Shutdown the API"""
    print("DEBUG: shutdown() called")
    
    try:
        api.shutdown()
        print("DEBUG: Sent shutdown command to API")
    except socket.error as e:
        print("DEBUG: Error during shutdown:", str(e))
        pass
    print("\nShutdown command relayed\n")

def UI(usrInput):
    """Main user menu"""
    global usrPrompt
    print("DEBUG: UI() called with usrInput:", usrInput)

    if usrInput in ("help", "h", "?"):
        print(' ')
        print('     -------------------------------------------------------------------------')
        print('     |        https://github.com/Dokument/PyBitmessage-Daemon                |')
        print('     |-----------------------------------------------------------------------|')
        print('     | Command                | Description                                  |')
        print('     |------------------------|----------------------------------------------|')
        print('     | help                   | This help file.                              |')
        print('     | apiTest                | Tests the API                                |')
        print('     | addInfo                | Returns address information (If valid)       |')
        print('     | bmSettings             | BitMessage settings                          |')
        print('     | exit                   | Use anytime to return to main menu           |')
        print('     | quit                   | Quits the program                            |')
        print('     |------------------------|----------------------------------------------|')
        print('     | listAddresses          | Lists all of the users addresses             |')
        print('     | generateAddress        | Generates a new address                      |')
        print('     | getAddress             | Get determinist address from passphrase      |')
        print('     |------------------------|----------------------------------------------|')
        print('     | listAddressBookEntries | Lists entries from the Address Book          |')
        print('     | addAddressBookEntry    | Add address to the Address Book              |')
        print('     | deleteAddressBookEntry | Deletes address from the Address Book        |')
        print('     |------------------------|----------------------------------------------|')
        print('     | subscribe              | Subscribes to an address                     |')
        print('     | unsubscribe            | Unsubscribes from an address                 |')
        print('     |------------------------|----------------------------------------------|')
        print('     | create                 | Creates a channel                            |')
        print('     | join                   | Joins a channel                              |')
        print('     | leave                  | Leaves a channel                             |')
        print('     |------------------------|----------------------------------------------|')
        print('     | inbox                  | Lists the message information for the inbox  |')
        print('     | outbox                 | Lists the message information for the outbox |')
        print('     | send                   | Send a new message or broadcast              |')
        print('     | unread                 | Lists all unread inbox messages              |')
        print('     | read                   | Reads a message from the inbox or outbox     |')
        print('     | save                   | Saves message to text file                   |')
        print('     | delete                 | Deletes a message or all messages            |')
        print('     -------------------------------------------------------------------------')
        print(' ')
        print("DEBUG: Displayed help menu")
        main()

    elif usrInput == "apitest":  # tests the API Connection.
        print("DEBUG: User requested API test")
        if apiTest():
            print('\n     API connection test has: PASSED\n')
            print("DEBUG: API test passed")
        else:
            print('\n     API connection test has: FAILED\n')
            print("DEBUG: API test failed")
        main()

    elif usrInput == "addinfo":
        print("DEBUG: User requested address info")
        tmp_address = userInput('\nEnter the Bitmessage Address.')
        print("DEBUG: User entered address:", tmp_address)
        
        try:
            address_information = json.loads(api.decodeAddress(tmp_address))
            print("DEBUG: Address information retrieved:", address_information)

            print('\n------------------------------')

            if 'success' in str(address_information['status']).lower():
                print(' Valid Address')
                print(' Address Version: %s' % str(address_information['addressVersion']))
                print(' Stream Number: %s' % str(address_information['streamNumber']))
                print("DEBUG: Valid address details displayed")
            else:
                print(' Invalid Address !')
                print("DEBUG: Invalid address")

            print('------------------------------\n')
        except Exception as e:
            print('\n     Error decoding address:', str(e), '\n')
            print("DEBUG: Error decoding address:", str(e))
        main()

    elif usrInput == "bmsettings":  # tests the API Connection.
        print("DEBUG: User requested Bitmessage settings")
        bmSettings()
        print(' ')
        main()

    elif usrInput == "quit":  # Quits the application
        print('\n     Bye\n')
        print("DEBUG: User quit application")
        sys.exit(0)

    elif usrInput == "listaddresses":  # Lists all of the identities in the addressbook
        print("DEBUG: User requested address list")
        listAdd()
        main()

    elif usrInput == "generateaddress":  # Generates a new address
        print("DEBUG: User requested address generation")
        uInput = userInput('\nWould you like to create a (D)eterministic or (R)andom address?').lower()
        print("DEBUG: User chose address type:", uInput)

        if uInput in ("d", "deterministic"):  # Creates a deterministic address
            deterministic = True

            lbl = ''
            passphrase = userInput('Enter the Passphrase.')  # .encode('base64')
            numOfAdd = int(userInput('How many addresses would you like to generate?'))
            addVNum = 3
            streamNum = 1
            isRipe = userInput('Shorten the address, (Y)es or (N)o?').lower()
            print("DEBUG: Collected deterministic address parameters - passphrase:", passphrase, "numOfAdd:", numOfAdd, "isRipe:", isRipe)

            if isRipe == "y":
                ripe = True
                print(genAdd(lbl, deterministic, passphrase, numOfAdd, addVNum, streamNum, ripe))
                main()
            elif isRipe == "n":
                ripe = False
                print(genAdd(lbl, deterministic, passphrase, numOfAdd, addVNum, streamNum, ripe))
                main()
            elif isRipe == "exit":
                usrPrompt = 1
                main()
            else:
                print('\n     Invalid input\n')
                print("DEBUG: Invalid ripe option")
                main()

        elif uInput == "r" or uInput == "random":  # Creates a random address with user-defined label
            deterministic = False
            null = ''
            lbl = userInput('Enter the label for the new address.')
            print("DEBUG: Collected random address parameters - label:", lbl)

            print(genAdd(lbl, deterministic, null, null, null, null, null))
            main()

        else:
            print('\n     Invalid input\n')
            print("DEBUG: Invalid address type")
            main()

    elif usrInput == "getaddress":  # Gets the address for/from a passphrase
        print("DEBUG: User requested deterministic address")
        phrase = userInput("Enter the address passphrase.")
        print('\n     Working...\n')
        print("DEBUG: Generating address from passphrase")
        address = getAddress(phrase, 4, 1)  # ,vNumber,sNumber)
        print('\n     Address: ' + address + '\n')
        print("DEBUG: Generated address:", address)
        usrPrompt = 1
        main()

    elif usrInput == "subscribe":  # Subsribe to an address
        print("DEBUG: User requested subscription")
        subscribe()
        usrPrompt = 1
        main()

    elif usrInput == "unsubscribe":  # Unsubscribe from an address
        print("DEBUG: User requested unsubscription")
        unsubscribe()
        usrPrompt = 1
        main()

    elif usrInput == "listsubscriptions":  # Unsubscribe from an address
        print("DEBUG: User requested subscription list")
        listSubscriptions()
        usrPrompt = 1
        main()

    elif usrInput == "create":
        print("DEBUG: User requested channel creation")
        createChan()
        usrPrompt = 1
        main()

    elif usrInput == "join":
        print("DEBUG: User requested channel join")
        joinChan()
        usrPrompt = 1
        main()

    elif usrInput == "leave":
        print("DEBUG: User requested channel leave")
        leaveChan()
        usrPrompt = 1
        main()

    elif usrInput == "inbox":
        print('\n     Loading...\n')
        print("DEBUG: User requested inbox")
        inbox()
        main()

    elif usrInput == "unread":
        print('\n     Loading...\n')
        print("DEBUG: User requested unread messages")
        inbox(True)
        main()

    elif usrInput == "outbox":
        print('\n     Loading...\n')
        print("DEBUG: User requested outbox")
        outbox()
        main()

    elif usrInput == 'send':  # Sends a message or broadcast
        print("DEBUG: User requested send message")
        uInput = userInput('Would you like to send a (M)essage or (B)roadcast?').lower()
        print("DEBUG: User chose message type:", uInput)

        if uInput in ('m', 'message'):
            null = ''
            sendMsg(null, null, null, null)
            main()
        elif uInput in ('b', 'broadcast'):
            null = ''
            sendBrd(null, null, null)
            main()
        else:
            print("DEBUG: Invalid message type")
            main()

    elif usrInput == "read":  # Opens a message from the inbox for viewing.
        print("DEBUG: User requested read message")
        uInput = userInput("Would you like to read a message from the (I)nbox or (O)utbox?").lower()
        print("DEBUG: User chose message location:", uInput)

        if uInput not in ('i', 'inbox', 'o', 'outbox'):
            print('\n     Invalid Input.\n')
            print("DEBUG: Invalid message location")
            usrPrompt = 1
            main()

        msgNum = int(userInput("What is the number of the message you wish to open?"))
        print("DEBUG: User selected message number:", msgNum)

        if uInput in ('i', 'inbox'):
            print('\n     Loading...\n')
            messageID = readMsg(msgNum)

            uInput = userInput("\nWould you like to keep this message unread, (Y)es or (N)o?").lower()
            print("DEBUG: User wants to keep message unread:", uInput)

            if uInput not in ('y', 'yes'):
                markMessageRead(messageID)
                print("DEBUG: Marked message as read")
                usrPrompt = 1

            uInput = userInput("\nWould you like to (D)elete, (F)orward, (R)eply to, or (Exit) this message?").lower()
            print("DEBUG: User chose message action:", uInput)

            if uInput in ('r', 'reply'):
                print('\n     Loading...\n')
                print(' ')
                replyMsg(msgNum, 'reply')
                print("DEBUG: User replied to message")
                usrPrompt = 1

            elif uInput in ('f', 'forward'):
                print('\n     Loading...\n')
                print(' ')
                replyMsg(msgNum, 'forward')
                print("DEBUG: User forwarded message")
                usrPrompt = 1

            elif uInput in ("d", 'delete'):
                uInput = userInput("Are you sure, (Y)es or (N)o?").lower()  # Prevent accidental deletion
                print("DEBUG: User confirmed deletion:", uInput)

                if uInput == "y":
                    delMsg(msgNum)
                    print('\n     Message Deleted.\n')
                    print("DEBUG: Message deleted")
                    usrPrompt = 1
                else:
                    usrPrompt = 1
            else:
                print('\n     Invalid entry\n')
                print("DEBUG: Invalid message action")
                usrPrompt = 1

        elif uInput in ('o', 'outbox'):
            readSentMsg(msgNum)
            print("DEBUG: Displayed sent message")

            # Gives the user the option to delete the message
            uInput = userInput("Would you like to (D)elete, or (Exit) this message?").lower()
            print("DEBUG: User chose sent message action:", uInput)

            if uInput in ("d", 'delete'):
                uInput = userInput('Are you sure, (Y)es or (N)o?').lower()  # Prevent accidental deletion
                print("DEBUG: User confirmed deletion:", uInput)

                if uInput == "y":
                    delSentMsg(msgNum)
                    print('\n     Message Deleted.\n')
                    print("DEBUG: Sent message deleted")
                    usrPrompt = 1
                else:
                    usrPrompt = 1
            else:
                print('\n     Invalid Entry\n')
                print("DEBUG: Invalid sent message action")
                usrPrompt = 1

        main()

    elif usrInput == "save":
        print("DEBUG: User requested save message")
        uInput = userInput("Would you like to save a message from the (I)nbox or (O)utbox?").lower()
        print("DEBUG: User chose message location to save:", uInput)

        if uInput not in ('i', 'inbox', 'o', 'outbox'):
            print('\n     Invalid Input.\n')
            print("DEBUG: Invalid message location")
            usrPrompt = 1
            main()

        if uInput in ('i', 'inbox'):
            try:
                inboxMessages = json.loads(api.getAllInboxMessages())
                numMessages = len(inboxMessages['inboxMessages'])
                print("DEBUG: Retrieved inbox messages for saving")
            except Exception as e:
                print('\n     Connection Error\n')
                print("DEBUG: Error retrieving inbox messages:", str(e))
                usrPrompt = 0
                main()

            while True:
                msgNum = int(userInput("What is the number of the message you wish to save?"))
                print("DEBUG: User selected message number:", msgNum)

                if msgNum >= numMessages:
                    print('\n     Invalid Message Number.\n')
                    print("DEBUG: Invalid message number")
                else:
                    break

            subject = inboxMessages['inboxMessages'][msgNum]['subject'].decode('base64')
            # Don't decode since it is done in the saveFile function
            message = inboxMessages['inboxMessages'][msgNum]['message']
            print("DEBUG: Retrieved message content for saving")

        elif uInput == 'o' or uInput == 'outbox':
            try:
                outboxMessages = json.loads(api.getAllSentMessages())
                numMessages = len(outboxMessages['sentMessages'])
                print("DEBUG: Retrieved outbox messages for saving")
            except Exception as e:
                print('\n     Connection Error\n')
                print("DEBUG: Error retrieving outbox messages:", str(e))
                usrPrompt = 0
                main()

            while True:
                msgNum = int(userInput("What is the number of the message you wish to save?"))
                print("DEBUG: User selected message number:", msgNum)

                if msgNum >= numMessages:
                    print('\n     Invalid Message Number.\n')
                    print("DEBUG: Invalid message number")
                else:
                    break

            subject = outboxMessages['sentMessages'][msgNum]['subject'].decode('base64')
            # Don't decode since it is done in the saveFile function
            message = outboxMessages['sentMessages'][msgNum]['message']
            print("DEBUG: Retrieved sent message content for saving")

        subject = subject + '.txt'
        saveFile(subject, message)
        print("DEBUG: Saved message to file")

        usrPrompt = 1
        main()

    elif usrInput == "delete":  # will delete a message from the system, not reflected on the UI.
        print("DEBUG: User requested delete message")
        uInput = userInput("Would you like to delete a message from the (I)nbox or (O)utbox?").lower()
        print("DEBUG: User chose message location to delete:", uInput)

        if uInput in ('i', 'inbox'):
            try:
                inboxMessages = json.loads(api.getAllInboxMessages())
                numMessages = len(inboxMessages['inboxMessages'])
                print("DEBUG: Retrieved inbox messages for deletion")
            except Exception as e:
                print('\n     Connection Error\n')
                print("DEBUG: Error retrieving inbox messages:", str(e))
                usrPrompt = 0
                main()

            while True:
                msgNum = userInput(
                    'Enter the number of the message you wish to delete or (A)ll to empty the inbox.').lower()
                print("DEBUG: User selected message to delete:", msgNum)

                if msgNum == 'a' or msgNum == 'all':
                    break
                elif int(msgNum) >= numMessages:
                    print('\n     Invalid Message Number.\n')
                    print("DEBUG: Invalid message number")
                else:
                    break

            uInput = userInput("Are you sure, (Y)es or (N)o?").lower()  # Prevent accidental deletion
            print("DEBUG: User confirmed deletion:", uInput)

            if uInput == "y":
                if msgNum in ('a', 'all'):
                    print(' ')
                    for msgNum in range(0, numMessages):  # processes all of the messages in the inbox
                        print('     Deleting message ', msgNum + 1, ' of ', numMessages)
                        delMsg(0)

                    print('\n     Inbox is empty.')
                    print("DEBUG: Deleted all inbox messages")
                    usrPrompt = 1
                else:
                    delMsg(int(msgNum))
                    print("DEBUG: Deleted single inbox message")

                print('\n     Notice: Message numbers may have changed.\n')
                main()
            else:
                usrPrompt = 1

        elif uInput in ('o', 'outbox'):
            try:
                outboxMessages = json.loads(api.getAllSentMessages())
                numMessages = len(outboxMessages['sentMessages'])
                print("DEBUG: Retrieved outbox messages for deletion")
            except Exception as e:
                print('\n     Connection Error\n')
                print("DEBUG: Error retrieving outbox messages:", str(e))
                usrPrompt = 0
                main()

            while True:
                msgNum = userInput(
                    'Enter the number of the message you wish to delete or (A)ll to empty the inbox.').lower()
                print("DEBUG: User selected message to delete:", msgNum)

                if msgNum in ('a', 'all'):
                    break
                elif int(msgNum) >= numMessages:
                    print('\n     Invalid Message Number.\n')
                    print("DEBUG: Invalid message number")
                else:
                    break

            uInput = userInput("Are you sure, (Y)es or (N)o?").lower()  # Prevent accidental deletion
            print("DEBUG: User confirmed deletion:", uInput)

            if uInput == "y":
                if msgNum in ('a', 'all'):
                    print(' ')
                    for msgNum in range(0, numMessages):  # processes all of the messages in the outbox
                        print('     Deleting message ', msgNum + 1, ' of ', numMessages)
                        delSentMsg(0)

                    print('\n     Outbox is empty.')
                    print("DEBUG: Deleted all outbox messages")
                    usrPrompt = 1
                else:
                    delSentMsg(int(msgNum))
                    print("DEBUG: Deleted single outbox message")
                print('\n     Notice: Message numbers may have changed.\n')
                main()
            else:
                usrPrompt = 1
        else:
            print('\n     Invalid Entry.\n')
            print("DEBUG: Invalid message location")
            usrPrompt = 1
            main()

    elif usrInput == "exit":
        print('\n     You are already at the main menu. Use "quit" to quit.\n')
        print("DEBUG: User tried to exit from main menu")
        usrPrompt = 1
        main()

    elif usrInput == "listaddressbookentries":
        print("DEBUG: User requested address book entries")
        res = listAddressBookEntries()
        if res == 20:
            print('\n     Error: API function not supported.\n')
            print("DEBUG: API function not supported")
        usrPrompt = 1
        main()

    elif usrInput == "addaddressbookentry":
        print("DEBUG: User requested add address book entry")
        address = userInput('Enter address')
        label = userInput('Enter label')
        print("DEBUG: User entered address:", address, "label:", label)
        
        res = addAddressToAddressBook(address, label)
        if res == 16:
            print('\n     Error: Address already exists in Address Book.\n')
            print("DEBUG: Address already exists")
        if res == 20:
            print('\n     Error: API function not supported.\n')
            print("DEBUG: API function not supported")
        usrPrompt = 1
        main()

    elif usrInput == "deleteaddressbookentry":
        print("DEBUG: User requested delete address book entry")
        address = userInput('Enter address')
        print("DEBUG: User entered address to delete:", address)
        
        res = deleteAddressFromAddressBook(address)
        if res == 20:
            print('\n     Error: API function not supported.\n')
            print("DEBUG: API function not supported")
        usrPrompt = 1
        main()

    elif usrInput == "markallmessagesread":
        print("DEBUG: User requested mark all messages read")
        markAllMessagesRead()
        usrPrompt = 1
        main()

    elif usrInput == "markallmessagesunread":
        print("DEBUG: User requested mark all messages unread")
        markAllMessagesUnread()
        usrPrompt = 1
        main()

    elif usrInput == "status":
        print("DEBUG: User requested client status")
        clientStatus()
        usrPrompt = 1
        main()

    elif usrInput == "shutdown":
        print("DEBUG: User requested shutdown")
        shutdown()
        usrPrompt = 1
        main()

    else:
        print('\n     "', usrInput, '" is not a command.\n')
        print("DEBUG: Invalid command entered:", usrInput)
        usrPrompt = 1
        main()

def main():
    """Entrypoint for the CLI app"""
    global api
    global usrPrompt
    print("DEBUG: main() called with usrPrompt:", usrPrompt)

    if usrPrompt == 0:
        print('\n     ------------------------------')
        print('     | Bitmessage Daemon by .dok  |')
        print('     | Version 0.3.1 for BM 0.6.2 |')
        print('     ------------------------------')
        print("DEBUG: Initializing API connection")
        api = xmlrpclib.ServerProxy(apiData())  # Connect to BitMessage using these api credentials

        if apiTest() is False:
            print('\n     ****************************************************************')
            print('        WARNING: You are not connected to the Bitmessage client.')
            print('     Either Bitmessage is not running or your settings are incorrect.')
            print('     Use the command "apiTest" or "bmSettings" to resolve this issue.')
            print('     ****************************************************************\n')
            print("DEBUG: API connection test failed")

        print('Type (H)elp for a list of commands.')  # Startup message)
        usrPrompt = 2

    elif usrPrompt == 1:
        print('\nType (H)elp for a list of commands.')  # Startup message)
        usrPrompt = 2

    try:
        user_input = raw_input('>').lower().replace(" ", "")
        print("DEBUG: User input received:", user_input)
        UI(user_input)
    except EOFError:
        print("DEBUG: EOF received, quitting")
        UI("quit")

if __name__ == "__main__":
    print("DEBUG: Starting Bitmessage CLI")
    main()
