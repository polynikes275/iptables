#!/usr/bin/python3

from os import getuid,system
from time import sleep
import argparse
import sys

# check privs for proper use
def checkprivs():
    if getuid() != 0:
        print("\nNeed to be root.\n")
        exit(1)
    else:
        pass

checkprivs()

# Install missing packages
def packages():
    ippers = "dpkg -l iptables-persistent"
    system(ippers)
    if ippers == 0:
        pass
    else:
        system(ippers)
        print("\n[+] Installing iptables-persistent [+]\n")
        sleep(2)
        install = "sudo apt-get install iptables-persistent -y"
        system(install)

    enable_service = "sudo systemctl enable netfilter-persistent.service"
    system(enable_service)
    if enable_service == 0:
        pass
    else:
        system(enable_service)

    print("\n[+] All packages installed [+]\n")
    sleep(2)

# setup loopback rules
def loopback():
    lback = "sudo iptables -A INPUT -i lo -j ACCEPT ; sudo iptables -A OUTPUT -o lo -j ACCEPT ; sudo iptables -A INPUT -s 127.0.0.8/8 -j DROP"
    system(lback)
    print("\n[+] Setting up loopback rules [+]\n")
    sleep(2)
    
    ip6 = "for i in INPUT FORWARD OUTPUT; do sudo ip6tables -P $i DROP; done"
    system(ip6)

# setup dns rules
def dns():
    dns_out = "sudo iptables -A OUTPUT -p udp -s {} -d {} --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.host, args.dns)
    system(dns_out)

    dns_in = "sudo iptables -A INPUT -p udp -s {} -d {} --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.dns, args.host)
    system(dns_in)

# setup host to any dest on tcp
def tcp_single():
    tcp_out = "sudo iptables -A OUTPUT -p {} -s {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.tcp, args.host, args.port)
    system(tcp_out)

    tcp_in = "sudo iptables -A INPUT -p {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.tcp, args.host, args.port)
    system(tcp_in)

# setup host to specific dest on tcp
def tcp_dual():
    tcp_out = "sudo iptables -A OUTPUT -p {} -s {} -d {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.tcp, args.host, args.dest, args.port)
    system(tcp_out)

    tcp_in = "sudo iptables -A INPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.tcp, args.dest, args.host, args.port)
    system(tcp_in)

# setup host to any on udp
def udp_single():
    udp_out = "sudo iptables -A OUTPUT -p {} -s {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.udp, args.host, args.port)
    system(udp_out)

    udp_in = "sudo iptables -A INPUT -p {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.udp, args.host, args.port)

# setup host to specific dest on udp
def udp_dual():
    udp_out = "sudo iptables -A OUTPUT -p {} -s {} -d {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.udp, args.host, args.dest, args.port)
    system(udp_out)

    udp_in = "sudo iptables -A INPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.udp, args.dest, args.host, args.port)

# drop policy
def drop():
    ip_drop = "for i in INPUT OUTPUT FORWARD; do sudo iptables -P $i {}; done".format(args.drop.upper())
    system(ip_drop)

# accept policy
def accept():
    ip_accept = "for i in INPUT OUTPUT FORWARD; do sudo iptables -P $i {}; done".format(args.accept.upper())
    system(ip_accept)

# flush iptables
def flush():
    ip_flush = "sudo iptables -F"
    system(ip_flush)

# list iptables
def list_tables():
    listTables = "sudo iptables -L -n"
    system(listTables)


def main():
    global args
    parser = argparse.ArgumentParser(usage="Set DNS: {0} -dns IP -host IP\
            \n\nusage: Set Host, TCP Port, TCP protocol: {1} -host IP -t tcp -P port#\
            \n\nusage: Set Host, UDP Port, UDP protocol: {2} -host IP -u udp -P port#\
            \n\nusage: Set Host, TCP Port, TCP Protocol, Dest IP: {3} -host IP -t tcp -P port# -dest IP\
            \n\nusage: Set Host, UDP Port, TCP Protocol, Dest IP: {4} -host IP -u udp -P port# -dest IP\
            \n\nusage: Install missing packages: {5} -pack pack\
            \n\nusage: Set All Policies to DROP: {6} -D DROP\
            \n\nusage: Set All Policies to ACCEPT: {7} -A ACCEPT\
            \n\nusage: Flush ipables: {8} -F FLUSH\
            \n\nusage: List iptables rules: {9} -L list".format(sys.argv[0].split('/')[-1],sys.argv[0].split('/')[-1],sys.argv[0].split('/')[-1], sys.argv[0].split('/')[-1], sys.argv[0].split('/')[-1],sys.argv[0].split('/')[-1], sys.argv[0].split('/')[-1], sys.argv[0].split('/')[-1], sys.argv[0].split('/')[-1], sys.argv[0].split('/')[-1]))
    parser.add_argument("-dns", dest="dns", help="DNS IP")
    parser.add_argument("-dest", dest="dest", help="Dest IP")
    parser.add_argument("-host", dest="host", help="Host IP")
    parser.add_argument("-t", dest="tcp", help="TCP Protocol")
    parser.add_argument("-u", dest="udp", help="UDP Protocol")
    parser.add_argument("-P", dest="port", help="Port")
    parser.add_argument("-pack", dest="pack", help="Use keyword 'pack'. Install missing packages")
    parser.add_argument("-D", dest="drop", help="Use keyword 'drop'. Set All policies to DROP")
    parser.add_argument("-A", dest="accept", help="Use keyword 'accept'. Set all policies to ACCEPT")
    parser.add_argument("-F", dest="flush", help="Use keyword 'flush'. Flush iptables")
    parser.add_argument("-L", dest="list", help="List iptables")
    args = parser.parse_args()

    if args.dns and args.host:
        loopback()
        dns()

    if args.host and args.tcp and args.port:
        tcp_single()

    if args.host and args.udp and args.port:
        udp_single()

    if args.dest and args.host and args.port and args.tcp:
        tcp_dual()

    if args.dest and args.host and args.port and args.udp:
        udp_dual()

    if args.pack:
        packages()

    if args.drop:
        drop()

    if args.accept:
        accept()

    if args.flush:
        flush()

    if args.list:
        list_tables()



if __name__ == '__main__':
    main()


