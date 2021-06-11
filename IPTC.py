import iptc, os, subprocess, fileinput

def Opening():
    print("==============================================================================")
    print("^===                   IPS Configuration - SynFlood                       ===^")
    print("============================================================================= ")
    print("= 1. Chain is used to forwarding packet (whatever you want to name it)       =")
    print("= 2. Homenet is the network that need to be protected (Ex. 192.168.1.0/24)   =")
    print("= 3. Extnet is which network need to filtered (Leave it 0.0.0.0/0, if        =")
    print("=    you're not sure)                                                        =")
    print("= 4. Interface input is the device of Extnet (check ifconfig)                =")
    print("= 5. Interface Output is the device of Homenet (check ifconfig)              =")
    print("==============================================================================")

def MakeChain(chain):
    table = iptc.Table(iptc.Table.FILTER)
    chain = table.create_chain(chain)

def MakeIPTC(chain, home, ext, ifin, ifout):
    try:
        oldRules = subprocess.check_output(["sudo","iptables","-D","FORWARD","1"])
        MakeIPTC(chain, home, ext, ifin, ifout)
    except  subprocess.CalledProcessError:
        os.popen('sudo iptables -I FORWARD -g IPS')
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain)
        rule = iptc.Rule()
        rule.in_interface = ifin
        rule.out_interface = ifout
        rule.src = ext
        rule.dst = home
        rule.protocol = "tcp"
        match = iptc.Match(rule, "tcp")
        match.dport = "80"
        match.sport = "49100:"
        rule.add_match(match)
        rule.target = iptc.Target(rule, "NFQUEUE")
        chain.insert_rule(rule)

def SuriConf(homenet):
    os.popen('sudo cp /etc/suricata/suricata.yaml /home/')
    filenames = ['/home/suricata.yaml']
    
    for line in fileinput.input(filenames, inplace=True):
        print line.replace('HOME_NET: "[', '#HOME_NET: "['),

    for line in fileinput.input(filenames, inplace=True):
        print line.replace('EXTERNAL_NET: "!$HOME_NET"', '#EXTERNAL_NET: "!$HOME_NET"'),

    for line in fileinput.input(filenames, inplace=True):
        print line.replace('#EXTERNAL_NET: "any"', 'EXTERNAL_NET: "any"'),

    for line in fileinput.input(filenames, inplace=True):
        print line.replace('#HOME_NET: "any"', '#HOME_NET: "any"\n    HOME_NET: "[' + homenet + ']"'),

    for line in fileinput.input(filenames, inplace=True):
        print line.replace('- suricata.rules', '#- suricata.rules'),

def CreatRules():
    bag1 = 'drop tcp $EXTERNAL_NET [49100:] <> $HOME_NET 80 '
    bag2 = '(flags: S; ack: 0; window: 8192; flow: to_server; detection_filter: track by_dst, count 20, seconds 10;'
    bag3 = ' classtype: attemted-dos; msg:"Possible DDoS Attack - SYNFlood"; sid:10000001;)'
    f = open("/home/suricata.rules", "w")
    f.write(bag1 + bag2 + bag3)
    f.close()

def RunSuri():
    try:
        value = subprocess.check_output(["pidof","suricata"])
        os.popen('sudo kill ' + value + '')
        RunSuri()
    except  subprocess.CalledProcessError:
        os.popen('suricata -c /home/suricata.yaml -S /home/suricara.rules -q 0 &')

if __name__== "__main__":
    Opening()
    chain = "IPS"
    homenet = raw_input("1. Homenet: ")
    extnet = raw_input("2. Extnet: ")
    inif = raw_input("3. Interface input: ")
    outif = raw_input("4. Interface output: ")
    
    table = iptc.Table(iptc.Table.FILTER)
    cha = iptc.Chain(table, chain)
    tab = table.is_chain(chain)

    if  tab == False:
        MakeChain(chain)
        MakeIPTC(chain, homenet, extnet, inif,outif)
        SuriConf(homenet)
        CreatRules()
        RunSuri()

    elif tab == True:
        MakeIPTC(chain, homenet, extnet, inif, outif)
        SuriConf(homenet)
        CreatRules()
        RunSuri()
