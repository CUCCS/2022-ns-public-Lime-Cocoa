import opcode
from scapy.all import *

dst_ip = "172.16.111.102"
dst_port = 53

resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port)/DNS(opcode=2),timeout=10)

if resp is None:
    print("Open|Filtered")
elif(resp.haslayer(UDP)):
    print("Open")
elif(resp.haslayer(ICMP)):
    if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code==3)):
        print("Closed")
    elif(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,9,10,13]):
        print("Filtered")
