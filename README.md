# Language-based Security

## Project - Man In The Middle Attack

### Introduction


### Goal of the project

The goal of the project is to demonstrate the vulnerability (insecure communications) of the HTTP and telnet protocols and why it is important to use their secure versions SSH and HTTPS. To do that, we will create a sniffing / spoofing python script from scratch (without using libraries like scapy or impacket). In the case of telnet, we will analyse the telnet TCP connection packets sent from the target to another remote machine to get the credentials. We will then send a crafted RST TCP connection packet (by spoofing the IP of the remote machine) to the target, in order to break up the telnet connection, before logging into the remote machine ourselves. In the case of HTTP, we will analyse the HTTP packets, containing credentials, sent from the target to a test website and send a spoofed 404 http error packet to the target before logging into his account.

It is a project written in python language that demonstrates application layer protocols’ vulnerabilities. Also, we will first take the point of view of an attacker by creating and executing the script and then switch to a defender’s point of view by discussing the possible countermeasures as we did in the labs.

### The Attack

#### Initial Configuration

In order to demonstrate how an attacker inside a private network could retrieve important information, we used three virtual machines (VirtualBox) to simulate connections between client and server inside a company, for example. We will have a machine running Ubuntu 16.04 as a client, and another machine running Ubuntu 16.04 as a server, with telnet client 
![Client's network information](assets/client-ip.png)

![Server's network information](assets/server-ip.png)

![Attacker's network information](assets/kali-ip.png)

#### ARP Spoofing

In order to perform 

![Telnet remote access](assets/telnet-connect.png)

![VirtualBox VMs](assets/virtualbox-vm.png)


#### Information Retrieving


### Countermeasures


### Discussion

### Conclusion

### Sources

1. [How To Do Man In The Middle Attack(MITM) with ARP Spoofing Using Python and Scapy](https://medium.com/@ravisinghmnnit12/how-to-do-man-in-the-middle-attack-mitm-with-arp-spoofing-using-python-and-scapy-441ee577ba1b)
2. [How to Prevent ARP Spoofing Attacks?](https://www.indusface.com/blog/protect-arp-poisoning/#Identify_the_Spoofing_Attack)

