from scapy.all import *

dst_ip = "172.16.111.102"
dst_port = 80

resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=10)

if resp is None:
    print("Open|Filtered")
elif(resp.haslayer(TCP)):
    if(resp.getlayer(TCP).flags==0x14):
        print("Closed")
    elif(resp.haslayer(ICMP)):
        if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("Filtered")
