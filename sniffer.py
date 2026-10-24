from collections import Counter
from scapy.arch.windows import get_windows_if_list
import scapy.all as scapy




def print_info(packet):
    print(packet.summary())


def analyse_packets(packets):
    ip_addresses = []    
    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_addresses.append(packet[scapy.IP].src)
            
            
    ip_counter = Counter(ip_addresses)
    print(ip_counter)


if __name__ == "__main__" :
    
    for iface in get_windows_if_list():
        print(iface["description"])  
    
    interface_name = input("network adapter to use : ")
    p = scapy.sniff(count=10, iface=interface_name, prn=print_info)
    analyse_packets(p)
    