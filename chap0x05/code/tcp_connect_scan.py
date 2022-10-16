from scapy.all import *

dst_ip = "172.16.111.102"
dst_port = 80

resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=10)

if resp is None:
    print("Filtered")
elif(resp.haslayer(TCP)):
    if(resp.getlayer(TCP).flags==0x12):
        send_ret = sr(IP(dst=dst_ip)/TCP(dport=dst_port,flags="AR"),timeout=10)
        print("Open")
    elif(resp.getlayer(TCP).flags==0x14):
        print("closed")
