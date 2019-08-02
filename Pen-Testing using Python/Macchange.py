#! usr/bin/env python

#Run commands using terminal
import subprocess

#To use options in terminal
import optparse

#importing regex for pattern matching
import re

def userinputs():

    parser = optparse.OptionParser()  # Create a parser object using OptionParser class

    # using add_option method to set up options expected , value entered stored in 'interface':
    parser.add_option('-i', '--interface', dest='interface', help='Interface to change its MacAddress')

    # using add_option method to set up options expected , value entered stored in 'new_mac':
    parser.add_option('-m', '--mac', dest='new_mac', help='New mac address')

    # parses the user input and returns two values
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify interface correctly use --help for info")
    elif not options.new_mac:
        parser.error("[-] Please specify mac correctly use --help for info")

    return options


def working(interface,new_mac):
    print('[+] Changing MAC address for ' + interface + ' to new mac')

    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw', 'ether', new_mac])
    subprocess.call(['ifconfig', interface, 'up'])

def checker(interface):
    ifconfig_result = str(subprocess.check_output(['ifconfig',interface]))

    mac_address_search_result = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w',ifconfig_result)

    if mac_address_search_result:
        print('[+] Current MAC address is -> ' + mac_address_search_result.group(0))
        return mac_address_search_result.group(0)

    else:
        print('[-] Could not find mac address')


options = userinputs()
old_mac = checker(options.interface)
working(options.interface,options.new_mac)
new_mac = checker(options.interface)

if (old_mac == new_mac):
    print('[-] Mac did not get changed ')
if (old_mac != new_mac):
    print('[+] Mac changed successfully')