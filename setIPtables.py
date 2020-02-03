#!/usr/bin/python3

"""
 Author: Jason B
 A simple iptables program to simply and quickly setup iptables
"""

from os import getuid,system
from time import sleep
import argparse
import sys

#default_location = "/etc/iptables/rules.v4"

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
    ippers = "dpkg -l iptables-persistent 1>&2 >/dev/null"
    if system(ippers) == 0:
        print("\n[+] iptables-persistent already installed [+]\n")
        pass
    else:
        system(ippers)
        print("\n[+] Installing iptables-persistent [+]\n")
        sleep(2)
        install = "sudo apt-get install iptables-persistent -y"
        system(install)

    enable_service = "sudo systemctl enable netfilter-persistent.service 1>&2 >/dev/null"
    if system(enable_service) == 0:
        print("\n[+] Iptables for persistence already enabled [+]\n")
        sleep(2)
        pass
    else:
        print("\n[+] Enabling iptables for persistence [+]\n")
        sleep(2)
        system(enable_service)

    print("\n[+] All packages installed [+]\n")
    sleep(2)

    print("\n***[WARNING] User must apt purge/disable ufw in order for iptables to function properly [WARNING]***\n")

# setup loopback rules
def loopback():
    lback = "for rule in INPUT FORWARD OUTPUT ; do sudo iptables -A $rule -m conntrack --ctstate INVALID -j DROP ; done ; sudo iptables -A INPUT ! -i lo --source 127.0.0.0/8 -j DROP"
    lback1 = "sudo iptables -A INPUT -i lo -j ACCEPT ; sudo iptables -A OUTPUT -o lo -j ACCEPT"
    system(lback)
    system(lback1)
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

    print("\n[+] Host -> {} to DNS Host -> {} using udp port 53 rule complete [+]\n".format(args.host, args.dns))


# setup host to any dest on tcp
def tcp_single():
    tcp_out = "sudo iptables -A OUTPUT -p {} -s {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.host, args.port)
    system(tcp_out)

    tcp_in = "sudo iptables -A INPUT -p {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.protocol, args.host, args.port)
    system(tcp_in)

    print("\n[+] Host -> {} to any Dest using tcp port {} rule complete [+]\n".format(args.host, args.port))


# setup host to specific dest on tcp
def tcp_dual():
    tcp_out = "sudo iptables -A OUTPUT -p {} -s {} -d {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.host, args.dest, args.port)
    system(tcp_out)

    tcp_in = "sudo iptables -A INPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.protocol, args.dest, args.host, args.port)
    system(tcp_in)

    print("\n[+] Host -> {} to Dest Host -> {} using tcp port {} rule complete [+]\n".format(args.host, args.dest, args.port))


# setup host to any on udp
def udp_single():
    udp_out = "sudo iptables -A OUTPUT -p {} -s {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.host, args.port)
    system(udp_out)

    udp_in = "sudo iptables -A INPUT -p {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.protocol, args.host, args.port)
    system(udp_in)

    print("\n[+] Host -> {} to any Dest using udp port {} rule complete [+]\n".format(args.host, args.dest, args.port))


# setup host to specific dest on udp
def udp_dual():
    udp_out = "sudo iptables -A OUTPUT -p {} -s {} -d {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.host, args.dest, args.port)
    system(udp_out)

    udp_in = "sudo iptables -A INPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.protocol, args.dest, args.host, args.port)
    system(udp_in)

    print("\n[+] Host -> {} to Dest Host -> {} using udp port {} rule complete [+]\n".format(args.host, args.dest, args.port))

# drop policy
def drop():
    ip_drop = "for i in INPUT OUTPUT FORWARD; do sudo iptables -P $i DROP; done"
    system(ip_drop)

    print("\n[+] iptables policies set to DROP [+]\n")

# accept policy
def accept():
    ip_accept = "for i in INPUT OUTPUT FORWARD; do sudo iptables -P $i ACCEPT; done"
    system(ip_accept)

    print("\n[+] iptables policies set to ACCEPT [+]\n")

# flush iptables
def flush():
    ip_flush = "sudo iptables -F"
    system(ip_flush)

    print("\n[+] iptables Flushed [+]\n")

# list iptables
def list_tables():
    listTables = "sudo iptables -L -n"
    system(listTables)

# Restore Iptables
def restore():
    restoreTables = "sudo iptables-restore < {}".format(default_location)
    system(restoreTables)

    print("\n[+] iptables restored from {} [+]\n".format(default_location))

# Save iptables
def saveTables():
    saving = "sudo iptables-save > {}".format(default_location)
    system(saving)

    print("\n[+] iptables saved -> {} [+]\n".format(default_location))

# main function
def main():
    global args
    global default_location
    default_location = "/etc/iptables/rules.v4"

    parser = argparse.ArgumentParser(usage="Set DNS: {0} -dns IP -host IP (default is udp port 53)\
            \n\nusage: Host to Any: {0} -host IP -p tcp/udp -P port#\
            \n\nusage: Host to Host: {0} -host IP -p tcp/udp -P port# -dest IP\
            \n\nusage: Install missing packages: {0} -pack\
            \n\nusage: Set All Policies to DROP: {0} -drop\
            \n\nusage: Set All Policies to ACCEPT: {0} -accept\
            \n\nusage: Flush ipables: {0} -flush\
            \n\nusage: List iptables rules: {0} -list\
            \n\nusage: Restore iptables: {0} -restore\
            \n\nusage: Save iptables: {0} -save".format(sys.argv[0].split('/')[-1]))
    parser.add_argument("-dns", dest="dns", help="DNS IP")
    parser.add_argument("-dest", dest="dest", help="Dest IP")
    parser.add_argument("-host", dest="host", help="Host IP")
    parser.add_argument("-p", dest="protocol", help="TCP/UDP Protocol")
    parser.add_argument("-P", dest="port", help="Port")
    parser.add_argument("-pack", action="store_true", help="UInstall missing packages")
    parser.add_argument("-drop", action="store_true", help="Set All policies to DROP")
    parser.add_argument("-accept", action="store_true", help="Set all policies to ACCEPT")
    parser.add_argument("-flush", action="store_true", help="Flush iptables")
    parser.add_argument("-list", action="store_true", help="List iptables")
    parser.add_argument("-restore", action="store_true", help="Restore iptables")
    parser.add_argument("-save", action="store_true", help="Save iptable rules")
    args = parser.parse_args()

    if args.dns and args.host:
        loopback()
        dns()

    if args.host and args.protocol == 'tcp' and args.port:
        tcp_single()

    if args.host and args.protocol == 'udp' and args.port:
        udp_single()

    if args.dest and args.host and args.port and args.protocol == 'tcp':
        tcp_dual()

    if args.dest and args.host and args.port and args.protocol == 'udp':
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

    if args.restore:
        restore()

    if args.save:
        saveTables()


if __name__ == '__main__':
    main()


