import scapy.all as scapy
import optparse as op
import subprocess as sp


    

def scan(ip):

    sp.call(['clear'])

    print('[+] Scanning ' + str(ip))

    arp_request = scapy.ARP(pdst=ip)

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/arp_request


    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    client_list = []

    for element in answered_list:

        client_dict = {"ip":element[1].psrc ,"mac":element[1].hwsrc}
        #psrc is ip address and hwdsrc is source mac address
        client_list.append(client_dict)

    return (client_list)


def printer(client_list):

    print('IP\t\t\tMAC Address\n---------------------------------------------------------')


    for client in client_list:

        print(client["ip"]+'\t\t'+client["mac"])



def scan_input():

    parser = op.OptionParser()

    parser.add_option('-i', dest = 'ip_in', help = 'Provide ip address to scan')

    (options,arguments) = parser.parse_args()

    return options.ip_in







ip_input = scan_input()

client_list = scan(ip_input)

printer(client_list)