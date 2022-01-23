#!/usr/bin/python3

"""
 Author: Jason Brewer
 A simple iptables/ip6tables program to simply and quickly configure iptables/ip6tables
 Defautl action is to DENY all IPv6 traffic
 
"""

from os import getuid,system
from time import sleep
import argparse
import sys
from subprocess import Popen, PIPE


# check privs for proper use
def checkprivs():
    if getuid() != 0:
        print("\nNeed to be root.\n")
        exit(1)

checkprivs()

# Install missing packages
def packages():

    # Checking for installation of iptables-persistent
    ippers = "dpkg -l iptables-persistent >/dev/null"
    value = Popen(ippers, stdout=PIPE, shell=True, universal_newlines=True)
    getValue = value.communicate()[0]
    returnCode = value.returncode
    if returnCode == 0:
        print("\n[+] iptables-persistent already installed [+]\n")
        pass
    else:
        print("\n[+] Installing iptables-persistent [+]\n")
        sleep(2)
        install = "sudo apt-get install iptables-persistent -y >/dev/null"
        getInstall = Popen(install, stdout=PIPE, shell=True, universal_newlines=True)
        sendCmd = getInstall.communicate()[0]
        returnCode = getInstall.returncode
        if returnCode == 0:
             print("\n[+] iptables-persistent has been installed! [+]\n")
        else:
            print("\n[-] Something went wrong during installation [-]\n")
            exit(0)

    # Checking to see if netfilter-persistent.service is enabled
    enable_service = "sudo systemctl enable netfilter-persistent.service >/dev/null"
    value = Popen(enable_service, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = value.communicate()[0]
    returnCode = value.returncode
    if returnCode == 0:
        print("\n[+] Iptables for persistence already enabled [+]")
        sleep(1)
        pass
    else:
        print("\n[+] Enabling iptables for persistence [+]")
        sleep(1)
        enable_service = "sudo systemctl enable netfilter-persistent.service >/dev/null"
        value = Popen(enable_service, shell=True, stdout=PIPE, universal_newlines=True)
        getValue = value.communicate()[0]
        returnCode = value.returncode
        if returnCode == 0:
            print("\n[+] Iptables for persistence is now enabled [+]\n")
        else:
            print("\n[-] Something went wrong enabling persistence for iptables [-]\n")
            exit(0)
        

    print("\n[+] All packages installed [+]\n")
    sleep(1)

    ufw_check = "which ufw >/dev/null"
    value = Popen(ufw_check, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = value.communicate()[0]
    returnCode = value.returncode
    if returnCode == 0:
        print("\n***[WARNING] User must apt purge ufw in order for iptables to function properly after reboot [WARNING]***\n")
    else:
        pass


# setup loopback rules
def loopback():

    lback = "for rule in INPUT FORWARD OUTPUT ; do sudo iptables -A $rule -m conntrack --ctstate INVALID -j DROP ; done ; sudo iptables -A INPUT ! -i lo --source 127.0.0.0/8 -j DROP"
    lback1 = "sudo iptables -A INPUT -i lo -j ACCEPT ; sudo iptables -A OUTPUT -o lo -j ACCEPT"
    Cmds = Popen(lback +';'+ lback1, shell=True, stdout=PIPE, universal_newlines=True)
    runCmds = Cmds.communicate()[0]
    returnCode = Cmds.returncode
    if returnCode == 0:
        print("\n[+] Setting up loopback rules [+]")
        sleep(2)
    else:
        print("\n[-] Error in setting up loopback rules [-]")
        exit()


# Setting a DROP all policy on ipv6tables
def ipv6Tables():

    ip6 = "for i in INPUT FORWARD OUTPUT; do sudo ip6tables -P $i DROP; done"
    cmd = Popen(ip6, shell=True, stdout=PIPE, universal_newlines=True)
    runcmd = cmd.communicate()[0]
    returnCode = cmd.returncode
    if returnCode == 0:
        print("\n[+] Set all ipv6 policies to DROP [+]\n")
    else:
        print("\n[-] Error in dropping ipv6 policies [-]\n")
        exit()


# setup dns rules
def dns(dnsAlt):

    dns_out = "sudo iptables -A OUTPUT -p {} -s {} -d {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.dns, dnsAlt)
    dns_in = "sudo iptables -A INPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".format(args.protocol, args.dns, args.source, dnsAlt)
    runCmds = Popen(dns_out +';'+ dns_in, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Host -> {} to DNS Host -> {} using udp port {} rule complete [+]\n".format(args.source, args.dns, args.port))
    else:
        print("\n[-] Error in setting up DNS [-]")
        exit()


# setup host to any dest on tcp
def tcp_single():

    tcp_out = "sudo iptables -A OUTPUT -p {} -s {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.port)
    tcp_in = "sudo iptables -A INPUT -p {} -d {} --sport {} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.port)
 
    runCmds = Popen(tcp_out +';'+tcp_in, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Host -> {} to any Dest using tcp port {} rule complete [+]\n".format(args.source, args.port))
    else:
        print("\n[-] Error in setting up host to any dest on tcp [-]")
        exit()


# setup host to specific dest on tcp
def tcp_dual():

    tcp_out = "sudo iptables -A OUTPUT -p {} -s {} -d {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.dest, args.port)
    tcp_in = "sudo iptables -A INPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".format(args.protocol, args.dest, args.source, args.port)
    runCmds = Popen(tcp_out +';'+ tcp_in, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Host -> {} to Dest Host -> {} using tcp port {} rule complete [+]\n".format(args.source, args.dest, args.port))
    else:
        print("\n[-] Error in setting up host to specific dest on tcp [-]")
        exit()


# setup host to any on udp
def udp_single():

    udp_out = "sudo iptables -A OUTPUT -p {} -s {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.port)
    udp_in = "sudo iptables -A INPUT -p {} -d {} --sport {} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.port)
    runCmds = Popen(udp_out +';'+ udp_in, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Host -> {} to any Dest using udp port {} rule complete [+]\n".format(args.source, args.port))
    else:
        print("\n[-] Error in setting up host to any on udp [-]")
        exit()


# setup host to specific dest on udp
def udp_dual():

    udp_out = "sudo iptables -A OUTPUT -p {} -s {} -d {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.dest, args.port)
    udp_in = "sudo iptables -A INPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".format(args.protocol, args.dest, args.source, args.port)
    runCmds = Popen(udp_out +';'+ udp_in, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Host -> {} to Dest Host -> {} using udp port {} rule complete [+]\n".format(args.source, args.dest, args.port))
    else:
        print("\n[-] Error in setting up host to specific dest on udp [-]")
        exit()


# drop policy for ipv4
def drop():

    ip_drop = "for i in INPUT OUTPUT FORWARD; do sudo iptables -P $i DROP; done"
    cmd = Popen(ip_drop, stdout=PIPE, shell=True, universal_newlines=True)
    getValue = cmd.communicate()[0].strip()
    returnCode = cmd.returncode
    if returnCode == 0:
        print("\n[+] iptables policies set to DROP [+]\n")
    else:
        print("\n[-] Error in setting iptables policy to drop [-]")
        exit()


# accept policy for ipv4
def accept():

    ip_accept = "for i in INPUT OUTPUT FORWARD; do sudo iptables -P $i ACCEPT; done"
    cmd = Popen(ip_accept, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = cmd.communicate()[0]
    returnCode = cmd.returncode
    if returnCode == 0:
        print("\n[+] iptables policies set to ACCEPT [+]\n")
    else:
        print("\n[-] Error in setting iptables polices to accept [-]")
        exit()


# flush iptables
def flush():

    if args.flush:
        ip_flush = "sudo iptables -F"
        cmd = Popen(ip_flush, shell=True, stdout=PIPE, universal_newlines=True)
        getValue = cmd.communicate()[0]
        returnCode = cmd.returncode
        if returnCode == 0:
            print("\n[+] iptables Flushed [+]\n")
        else:
            print("\n[-] Error in flushing iptables [-]")
            exit()

    elif args.flush6:
        ip_flush = "sudo ip6tables --flush"
        cmd = Popen(ip_flush, shell=True, stdout=PIPE, universal_newlines=True)
        getValue = cmd.communicate()[0]
        returnCode = cmd.returncode
        if returnCode == 0:
            print("\n[+] ip6tables Flushed [+]\n")
        else:
            print("\n[-] Error in flushing iptables [-]")
            exit()


# list iptables
def list_tables():
    
    if args.list:
        listTables = "sudo iptables -L --line-numbers -n"
        cmd = Popen(listTables, shell=True, stdout=PIPE, universal_newlines=True)
        getValue = cmd.communicate()[0].strip()
        returnCode = cmd.returncode
        if returnCode == 0:
            print(getValue)
        else:
            print("\n[-] Error in iptables rules [-]")
            exit()

    elif args.list6:
        listTables6 = "sudo ip6tables --list"
        cmd = Popen(listTables6, shell=True, stdout=PIPE, universal_newlines=True)
        getValue = cmd.communicate()[0].strip()
        returnCode = cmd.returncode
        if returnCode == 0:
            print(getValue)
        else:
            print("\n[-] Error in iptables rules [-]")
            exit()


# Restore Iptables
def restore(restoreName):

    restoreTables = Popen("sudo iptables-restore {} 2>/dev/null".format(default_location+restoreName), stdout=PIPE, shell=True, universal_newlines=True)
    statCode = restoreTables.communicate()[0].strip()
    rc = restoreTables.returncode
    if rc != 0:
        print("\n[-] Error in restoring iptables. File not found error [ {} ] [-]\n".format(restoreName))
        exit(0)
    print("\n[+] iptables restored from {} [+]\n".format(default_location+restoreName))


# Save iptables
def saveTables(tableName):

    saving = "sudo iptables-save > {}".format(default_location+tableName)
    cmd = Popen(saving, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = cmd.communicate()[0]
    returnCode = cmd.returncode
    if returnCode == 0:
        print("\n[+] Saving to {} [+]\n".format(default_location+tableName))
    else:
        print("\n[-] Error in saving iptables to {} [-]\n".format(default_location+tableName))
        exit()


# Show packet count per rule
def packet_count():

    count = "sudo iptables -Z ; sudo watch iptables -L -n -v"
    print("\n[+] Packet Count is being zeroed out for each Policy [+]\n\n[+] Press Ctrl-C to stop watching [+]\n")
    timer()
    system(count)


# Show timer countdown
def timer():

    print("[+] Showing Packet Count in...[+]", flush=True)
    for num in range(1,6):
        print(6-num,end=' ', flush=True)
        sleep(1)
    print("\n\n")


# Show names of rules saved
def show():

    print("\n[+] Showing saved iptables rules file names [+]\n")
    showNames = "ls -l /etc/iptables"
    cmd = Popen(showNames, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = cmd.communicate()[0]
    returnCode = cmd.returncode
    if returnCode == 0:
        print(getValue)
    else:
        print("[-] Error in showing names of saved iptables rules files [-]")
        exit() 


# Allow inbound ssh connections not originating from host
def sshIn():

    inbound = "sudo iptables -A INPUT -p {} -s {} -d {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.dest, args.port)
    outbound = "sudo iptables -A OUTPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".format(args.protocol, args.dest, args.source, args.port)
    runCmds = Popen(inbound +';'+ outbound, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Inbound ssh connection from {} to -> {} on port {} completed [+]\n".format(args.source, args.dest, args.port))
    else:
        print("\n[-] Error in setting up inbound ssh connections not originating from host [-]")
        exit()


# Allow outbound ssh connections originating from host
def sshOut():

    inbound = "sudo iptables -A INPUT -p {} -s {} -d {} --dport {} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".format(args.protocol, args.dest, args.source, args.port)
    outbound = "sudo iptables -A OUTPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.dest, args.port)
    runCmds = Popen(inbound +';'+ outbound, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Outbound ssh connection from {} to -> {} on port {} completed [+]\n".format(args.source, args.dest, args.port))
    else:
        print("\n[-] Error in setting up outbound ssh connections originating from host [-]")
        exit()


# main function
def main():
    global args
    global default_location
    default_location = "/etc/iptables/"
    global tableName
    global restoreName
    global dnsAlt

    parser = argparse.ArgumentParser(description="[###] An easier way to setup and configure iptables using the conntrack module [###] The conntrack module keeps track of connections (connections state) [###] Ensure you save your iptables so that they are persistent upon reboot",
            usage="""First set DNS: {0} -dns IP -src IP -p udp -P port\
            \n\nusage: Host to Any: {0} -src IP -p tcp/udp -P port\
            \n\nusage: Host to Host: {0} -src IP -p tcp/udp -P port -dest IP\
            \n\nusage: Restore iptables: {0} -restore fileName\
            \n\nusage: Save iptables: {0} -save fileName\
            \n\nusage: Establish incoming ssh connection NOT originating from host: {0} -sshIn -src IP -dest IP -p tcp -P port\
            \n\nusage: Establish outbound ssh connection originating from host: {0} -sshOut -src IP -dest IP -p tcp -P port""".format(sys.argv[0].split('/')[-1]))
            
    parser.add_argument("-dns", dest="dns", help="DNS IP *SET THIS FIRST*")
    parser.add_argument("-dest", dest="dest", help="Dest IP")
    parser.add_argument("-src", dest="source", help="Source IP")
    parser.add_argument("-p", dest="protocol", help="TCP/UDP Protocol")
    parser.add_argument("-P", dest="port", help="TCP/UDP Port")
    parser.add_argument("-pack", action="store_true", help="Install missing packages")
    parser.add_argument("-drop", action="store_true", help="Set all IPv4 policies to DROP")
    parser.add_argument("-drop6", action="store_true", help="Set all IPv6 policies to DROP")
    parser.add_argument("-accept", action="store_true", help="Set all IPv4 policies to ACCEPT")
    parser.add_argument("-flush", action="store_true", help="Flush iptables")
    parser.add_argument("-flush6", action="store_true", help="Flush iptables")
    parser.add_argument("-list", action="store_true", help="List IPv4 iptables rules")
    parser.add_argument("-list6", action="store_true", help="List IPv6 iptables rules")
    parser.add_argument("-restore", dest="Restore_savedFile", help="Restore iptables")
    parser.add_argument("-save", dest="Saved_fileName", help="Save iptables rules in default location (/etc/iptables/) with file name you provide")
    parser.add_argument("-count", action="store_true", help="Show packet count for each policy")
    parser.add_argument("-show", action="store_true", help="Show saved iptables rules file names")
    parser.add_argument("-sshIn", action="store_true", help="Establish new incoming ssh connections NOT originating from your host\nFor added security, use keybased authentication instead of passwords.\nMoreover, make sure destination host has public key of sending host")
    parser.add_argument("-sshOut", action="store_true", help="Establish new outgoing ssh connection originating from your host")
    args = parser.parse_args()

    if args.dns:#and args.source and args.port and args.protocol:
        if args.port != 53:
            dnsAlt = args.port
            loopback()
            dns(dnsAlt)
            exit()
        else:
            loopback()
            dns(dnsAlt)
            exit()

    if args.sshIn:
        sshIn()
        exit()
    
    if args.sshOut:
        sshOut()
        exit()

    if args.source and args.protocol == 'tcp' and args.port and not args.sshIn and not args.sshOut and not args.dest:
        tcp_single()
        exit()

    if args.source and args.protocol == 'udp' and args.port and not args.sshIn and not args.sshOut and not args.dest:
        udp_single()
        exit()

    if args.dest and args.source and args.port and args.protocol == 'tcp': 
        tcp_dual()
        exit()

    if args.dest and args.source and args.port and args.protocol == 'udp':
        udp_dual()
        exit()

    if args.pack:
        packages()
        exit()

    if args.drop:
        drop()
        exit()

    if args.drop6:
       ipv6Tables()
       exit() 

    if args.accept:
        accept()
        exit()

    if args.flush:
        flush()

    if args.flush6:
        flush()

    if args.list:
        list_tables()
        exit()

    if args.list6:
        list_tables()
        exit()

    if args.Restore_savedFile:
        restoreName = args.Restore_savedFile
        restore(restoreName)
        exit()

    if args.Saved_fileName:
        tableName = args.Saved_fileName
        saveTables(tableName)
        exit()

    if args.count:
        packet_count()
        exit()

    if args.show:
        show()
        exit()


if __name__ == '__main__':
    main()


