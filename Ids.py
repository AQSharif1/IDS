"""""
Arthor: Abdul
Term Project network/port scanner with detection
I constructed an application that allows user to scan network 
and detect other devices connected to same network as well
as a port scanner that determines open ports which can show 
potential vulnerabilities
Had difficulties implementing YARA for malware detection

"""

from scapy.all import ARP
from scapy.all import Ether
from scapy.all import srp
from scapy.all import ls
import scapy.all
import sys
import socket
from datetime import datetime
import csv

import yara

#filepath = open('C:\\Users\\Abdul\\Desktop\\yaraRule.txt', "r", encoding='utf-8')
#rules = yara.compile(filepath)

#Create socket
sockets = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Add ip from terminal
if len(sys.argv) > 1:
    ip = sys.argv[1]
else:
    print("No arguments. Terminal Run Example: py filename.py [IP Address]")
    exit()


#ARP request frame with destination ip
arp = ARP(pdst=ip)
print(arp.show())

# request packet aasking who has ip
print(arp.summary())


# create Ether broadcast packet
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
print("\n\n**********************************")
print(ether.show())
print(ether.summary())
print("\n\n")
# stack them
packet = ether/arp

result = srp(packet, timeout=3, verbose=0)[0]

print("\n\n*****************************")
print(result.show())

# a list of clients, we will fill this in the upcoming loop
clients = []

for sent, received in result:
    # for each response, append ip and mac address to `clients` list
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})


print('Total Number of Responses ->', len(result))

if ip != '127.0.0.1':
    print('Number of Answered Responsed ->', len(result[0]))

    
# print clients
print("Devices Available in this network:")
print("IP Address" + "\t    "+"MAC Adress")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))
     

print("\n\n\nScan Port\n")
print("*******************************************")

value = input("Do you want to scan all ports? Yes or No: ")

print("Reply: "+ value);
if value == "yes" :

    print("\n\nScanning All Ports in ip: " + ip + "\n")
    print("*******************************************")
    print("Scan Start Time: " + str(datetime.now()))
    print("*******************************************")

    for port in range(1,65535):
        socket.setdefaulttimeout(1)
        re = sockets.connect_ex((ip,port))
        if re == 0:
            print("Port {} is open".format(port))
            sockets.close()
        elif re != 0:
                print("Port {} is used".format(port))
                sockets.close()
elif value == "no": 
    answer = input("Do you want to scan to a certain port? Yes or No?")
    if answer == "yes":
        newVal = input("To what port?    1- ? (1 to what port?")
        print("\n\nScanning to Port " + newVal + "\n")
        print("*******************************************")
        print("Scan start time: " + str(datetime.now()))
        print("*******************************************")
        for port in range(1,int(newVal)+1):
            socket.setdefaulttimeout(1)
            re = sockets.connect_ex((ip,port))
            if re == 0:
                print("Port {} is open".format(port))
                sockets.close()
            elif re != 0:
               # print("Port {} is being used".format(port))
                sockets.close()
           
    if answer == "no":    
        print("No was selected, Bye.")
else :
    print("INVALID INPUT, SYSTEM EXIT BYE.")
    sys.exit();
  
if answer != "no":    
    print("Scan Finish time:" + str(datetime.now()));
sys.exit()

