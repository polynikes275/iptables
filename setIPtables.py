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
        print("\nNeed to be UID/EUID 0 (root).\n")
        exit(1)

checkprivs()

# Install missing packages
def packages():

    # Checking for installation of iptables-persistent
    persistentCheck = "dpkg -s iptables-persistent 2>/dev/null"
    value = Popen(persistentCheck, stdout=PIPE, shell=True, universal_newlines=True)
    getValue = value.communicate()[0]
    returnCode = value.returncode
    if returnCode == 0:
        print("\n[+] iptables-persistent already installed [+]\n")
        pass
    else:
        print("\n[+] Installing iptables-persistent [+]\n")
        sleep(1)
        install = "sudo apt install iptables-persistent netfilter-persistent"
        getInstall = Popen(install, stdout=PIPE, shell=True, universal_newlines=True)
        sendCmd = getInstall.communicate()[0]
        returnCode = getInstall.returncode
        if returnCode == 0:
             print("\n[+] iptables-persistent and netfilter-persistent has been installed! [+]\n")
        else:
            print("\n[-] Something went wrong during installation [-]\n")
            exit(0)

    # Checking to see if netfilter-persistent.service is enabled
    enable_service = "sudo systemctl is-enabled netfilter-persistent.service >/dev/null"
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
    dns_in = "sudo iptables -A INPUT -p {} -s {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.protocol, args.dns, args.source, dnsAlt)
    runCmds = Popen(dns_out +';'+ dns_in, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Host -> {} to DNS Host -> {} using udp port {} rule complete [+]\n".format(args.source, args.dns, args.port))
    else:
        print("\n[-] Error in setting up DNS [-]")
        exit()


# setup host to any dest on tcp
def singleConn(prot,src,prt):

    conn_out = "sudo iptables -A OUTPUT -p {} -s {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(prot, src, prt)
    conn_in = "sudo iptables -A INPUT -p {} -d {} --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(prot, src, prt)
 
    runCmds = Popen(conn_out +';'+conn_in, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Host -> {} to any Dest using {} port {} rule complete [+]\n".format(args.source, args.protocol, args.port))
    else:
        print("\n[-] Error in setting up host to any dest on {} {} [-]".format(args.protocol, args.port))
        exit()


# setup host to specific dest on tcp
def dualConn():

    conn_out = "sudo iptables -A OUTPUT -p {} --match multiport --dport {} -s {} -d {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.port, args.source, args.dest)
    # Testing to see if --match multiport --sport works 
    conn_in = "sudo iptables -A INPUT -p {} --match multiport --sport {} -s {} -d {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(args.protocol, args.port, args.dest, args.source)
    runCmds = Popen(conn_out +';'+ conn_in, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Host -> {} to Dest Host -> {} using {} port {} rule complete [+]\n".format(args.source, args.dest, args.protocol, args.port))
    else:
        print("\n[-] Error in setting up host to specific dest on {} {} [-]\n".format(args.protocol,args.port))
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

def accept6():

    ip_accept = "for i in INPUT OUTPUT FORWARD; do sudo ip6tables -P $i ACCEPT; done"
    cmd = Popen(ip_accept, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = cmd.communicate()[0]
    returnCode = cmd.returncode
    if returnCode == 0:
        print("\n[+] ip6tables policies set to ACCEPT [+]\n")
    else:
        print("\n[-] Error in setting iptables polices to accept [-]")
        exit()


# flush iptables
def flush():

    if args.flush:
        ip_flush = "for i in INPUT OUTPUT FORWARD; do sudo iptables -P $i ACCEPT; done; sudo iptables -F"
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
            print("\n[-] Error in ip6tables rules [-]")
            exit()


# Restore Iptables
def restore():

    restoreTables = Popen("sudo iptables-restore {} 2>/dev/null".format(default_location), stdout=PIPE, shell=True, universal_newlines=True)
    statCode = restoreTables.communicate()[0].strip()
    rc = restoreTables.returncode
    if rc != 0:
        print("\n[-] Error in restoring iptables. File not found error [ {} ] [-]\n".format(default_location))
        exit(0)
    print("\n[+] iptables restored from {} [+]\n".format(default_location))


# Save iptables
def saveTables():

    saving = "sudo iptables-save > {}".format(default_location)
    cmd = Popen(saving, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = cmd.communicate()[0]
    returnCode = cmd.returncode
    if returnCode == 0:
        print("\n[+] Saving to {} [+]\n".format(default_location))
    else:
        print("\n[-] Error in saving iptables to {} [-]\n".format(default_location))
        exit()


# Show packet count per rule
def packet_count():

    count = "sudo iptables -Z ; sudo watch -n .01 iptables -L -n -v"
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

    inbound = "sudo iptables -I INPUT 5 -p {} -s {} -d {} --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(args.protocol, args.source, args.dest, args.port)
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


def createLoggingChain(ruleName,comment):

    rule = "sudo iptables -N {}".format(ruleName)
    genlog = "sudo iptables -A {} -m limit --limit 2/min -j LOG --log-prefix '{}'".format(ruleName,comment)
    drop = "sudo iptables -A {} -j DROP".format(ruleName)
    setlog = ''
    if ',' in args.port:
        setlog = "sudo iptables -A INPUT -d {} -p tcp --match multiport --dport {} -j {}".format(args.dest, args.port, ruleName)
    elif ':' in args.port:
        setlog = "sudo iptables -A INPUT -d {} -p tcp --match multiport --dport {} -j {}".format(args.dest, args.port, ruleName)
    elif ',' not in args.port or ':' not in args.port:
        setlog = "sudo iptables -A INPUT -d {} -p tcp --match multiport --dport {} -j {}".format(args.dest, args.port, ruleName)
    runCmds = Popen(rule +';'+ genlog +';'+ drop + ';' + setlog, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode 
    if returnCode == 0:
        print("\n[+] Logging enabled for {}\n".format(ruleName))
    else:
        print("\n[-] Error in setting up chain rule for logging [-]\n")
        exit()


def deleteChain(chainName):

    chain = "sudo iptables -F"
    chainDel = "sudo iptables -X {}".format(chainName)
    runCmds = Popen(chain+';'+chainDel, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Chain Deleted {}\n".format(chainName))
    else:
        print("[-] Error in deleting chain {}".format(chainName))
        exit()        


def portScan():

    # Drop ssh attempts where the attempts are greater than 10 per minute
    blockSSH = "sudo iptables -A INPUT -p tcp --match multiport --dport {} -m conntrack --ctstate NEW -m recent --set".format(args.port)
    blockSSH1 = "sudo iptables -A INPUT -p tcp --match multiport --dport {} -m conntrack --ctstate NEW -m recent --update --seconds 20 --hitcount 10 -j DROP".format(args.port)

    # Protect against a SYN flood attack to limiting the number of inbound connections to n value per second
    synFlood = "sudo iptables -A INPUT -m conntrack --ctstate NEW -p tcp -m tcp --syn -m recent --name synflood --set"
    synFlood1 = "sudo iptables -A INPUT -m conntrack --ctstate NEW -p tcp -m tcp --syn -m recent --name synflood --update --seconds 1 --hitcount 30 -j DROP"

    # Protect against Christmas tree scan, syn scan, syn/ack, null scan
    christmas = "sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -m limit --limit 1/min -j LOG --log-prefix '[!!!] Xmas scan [!!!]'"
    christmasDrop = "sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP"
    synscan = "sudo iptables -A INPUT -p tcp --tcp-flags ALL SYN -m limit --limit 1/min -j LOG --log-prefix '[!!!] SYN SCAN [!!!]'"
    synscanDrop = "sudo iptables -A INPUT -p tcp --tcp-flags ALL SYN -j DROP"
    synack = "sudo iptables -A INPUT -p tcp --tcp-flags ALL SYN,ACK -m limit --limit 1/min -j LOG --log-prefix '[!!!] SYN/ACK SCAN [!!!]'"
    synackDrop = "sudo iptables -A INPUT -p tcp --tcp-flags ALL SYN,ACK -j DROP"
    nullscan = "sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 1/min -j LOG --log-prefix '[!!!] NULL SCAN [!!!]'"
    nullscanDrop = "sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP"

    # Prevent Smurf attack by dropping certain icmp types/codes 
    blockSmurfAttack ="sudo iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP"
    blockSmurfAttack2 = "sudo iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP"
    blockSmurfAttack3 = "sudo iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT"
   
    # Block port scanning hosts for n duration (24 hours in the below (in seconds))
    blockScan = "sudo iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP"
    blockScan1 = "sudo iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP"

    # Remove offending hosts after n duration from above
    removeHosts = "sudo iptables -A INPUT -m recent --name portscan --remove"
    removeHosts1 = "sudo iptables -A FORWARD -m recent --name portscan --remove"

    
    runCmds = Popen(blockSSH+';'+blockSSH1+';'+synFlood+';'+synFlood1+';'+christmas+';'+christmasDrop+';'+synscan+';'+synscanDrop+';'+synack+';'+synackDrop+';'+nullscan+';'+nullscanDrop+';'+blockSmurfAttack+';'+blockSmurfAttack2+';'+blockSmurfAttack3+';'+blockScan+';'+blockScan1+';'+removeHosts+';'+removeHosts1, shell=True, stdout=PIPE, universal_newlines=True)
    getValue = runCmds.communicate()[0]
    returnCode = runCmds.returncode
    if returnCode == 0:
        print("\n[+] Defensive actions implemented\n")
    else:
        print("[-] Error in setting port scan rules")
        exit()        
    

# main function
def main():
    global args
    global default_location
    default_location = "/etc/iptables/rules.v4"
    global dnsAlt
    global ruleName
    global chainName


    parser = argparse.ArgumentParser(description="[###] An easier way to setup and configure iptables using the conntrack module [###] The conntrack module keeps track of connections (connections state) [###] Ensure you save your iptables so that they are persistent upon reboot",
            usage="""First set DNS: {0} -dns IP -src IP -p udp -P port\
            \n\nusage: Host to Any: {0} -src IP -p tcp/udp -P port\
            \n\nusage: Host to Host: {0} -src IP -p tcp/udp -P port -dest IP\
            \n\nusage: Restore iptables: {0} -restore\
            \n\nusage: Save iptables: {0} -save\
            \n\nusage: Block/Defend: {0} -block -P sshPort\
            \n\nusage: Create logging for ssh: {0} -log logfilename -dest IP -P sshport(s) [separate ports with a comma] -comment "comment here"\
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
    parser.add_argument("-accept6",action="store_true", help-"Set all IPv6 polices to ACCEPT")
    parser.add_argument("-block", action="store_true", help="Log and block ssh attempts, port scans, and other attacks")
    parser.add_argument("-comment",dest="logprefix", help="Supply a log-prefix to search for in /var/log/syslog")
    parser.add_argument("-flush", action="store_true", help="Flush iptables")
    parser.add_argument("-flush6", action="store_true", help="Flush iptables")
    parser.add_argument("-list", action="store_true", help="List IPv4 iptables rules")
    parser.add_argument("-list6", action="store_true", help="List IPv6 iptables rules")
    parser.add_argument("-log", dest="logfile", help="Create a log chain for erroneous ssh conection attempts, port scans, etc.,")
    parser.add_argument("-chain", dest="chainName", help="[!!!] Caution: Your current rules will be flushed. Delete a chain you created.")
    parser.add_argument("-restore", action="store_true", help="Restore iptables")
    parser.add_argument("-save", action="store_true", help="Save iptables rules in default location (/etc/iptables/rules.v4)")
    parser.add_argument("-count", action="store_true", help="Show packet count for each policy")
    parser.add_argument("-show", action="store_true", help="Show saved iptables rules file names")
    parser.add_argument("-sshIn", action="store_true", help="Establish new incoming ssh connections NOT originating from your host\nFor added security, use keybased authentication instead of passwords.\nMoreover, make sure destination host has public key of sending host")
    parser.add_argument("-sshOut", action="store_true", help="Establish new outgoing ssh connection originating from your host")
    args = parser.parse_args()

    if args.dns:#and args.protocol != '' and args.source != '' and args.port != '':

        if args.port != 53:
            dnsAlt = args.port
            loopback()
            dns(dnsAlt)
            exit()
        elif args.port == 53:
            loopback()
            dns(dnsAlt)
            exit()


    if args.source and not args.dest:
        prot,src,prt = args.protocol, args.source, args.port
        singleConn(prot,src,prt)
        exit()

    if args.dest and args.source and args.protocol and args.port: 
        dualConn()
        exit()

    elif args.sshIn:
        sshIn()
        exit()
    
    elif args.sshOut:
        sshOut()
        exit()

    elif args.pack:
        packages()
        exit()

    elif args.drop:
        drop()
        exit()

    elif args.drop6:
       ipv6Tables()
       exit() 

    elif args.accept:
        accept()
        exit()

    elif args.accept:
        accept6()
        exit()

    elif args.flush:
        flush()
        exit()

    elif args.flush6:
        flush()
        exit()

    elif args.list:
        list_tables()
        exit()

    elif args.list6:
        list_tables()
        exit()

    elif args.restore:
        restore()
        exit()

    elif args.save:
        saveTables()
        exit()

    elif args.count:
        packet_count()
        exit()

    elif args.show:
        show()
        exit()

    elif args.logfile and args.dest:
        ruleName = args.logfile.upper()
        comment = args.logprefix
        createLoggingChain(ruleName,comment) 
        exit()

    elif args.chainName:
        deleteChain(args.chainName)
        exit()        

    elif args.block:
        portScan()
        exit()


if __name__ == '__main__':
    main()


