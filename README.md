# PowerNetScan

Script perform simple TCP port scanning using multithreading.

## Table of Contents
- [Project Overview](#project-overview)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Acknowledgments](#acknowledgments)
- [ToDo](#todo)
- [Licence](#licence)

## Project Overview

Script performs TCP port scanning based on an asynchronous connection. It is used TcpClient object from System.Net.Sockets assembly.
Before starting TCP scanning the whole scope (hosts and ports) is validated. It is possible to pass hosts list via argument OR file.
There are three types to show results - console output, save to file or retrun object.

More detalied explanation at https://r2alter.github.io/PowerNetScan/

## Getting Started

Just download script and load it as module.

```(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/r2alter/PowerNetScan/main/PowerNetScan.ps1') | IEX```

### Prerequisites

- PowerShell version 2.0 or higher.
- Availability of .NET Framework classes.

## Usage

```
PS> Invoke-TCPPortScan -Hosts google.com,amazon.com -Threads 50

PowerNetScan started at: 12/19/2023 09:37:40 with command: Invoke-TCPPortScan -Hosts google.com,amazon.com -Threads 50 
Task finished at 12/19/2023 09:37:50 and scanning time was: 9 seconds, 863 milliseconds.

PowerNetScan scan results:
Totally scanned 4 hosts.
Did NOT perform ping check.

142.250.186.206 (google.com) open ports:
80
443
-----------
205.251.242.103 (amazon.com) open ports:
443
80
-----------
52.94.236.248 (amazon.com) open ports:
80
443
-----------
54.239.28.85 (amazon.com) open ports:
443
80
-----------
```

```
PS> Invoke-TCPPortScan -Hosts google.com -Ports 21,22,80,443,8080 -Verbose 

VERBOSE: Parsing input.
VERBOSE: Source of targets - script argument.
VERBOSE: Scan scope summary: 1 hosts / 5 portInvoke-TCPPortScan -Hosts google.com -Ports 21,22,80,443,8080 -Verbose s.
PowerNetScan started at: 12/19/2023 09:45:46 with command: Invoke-TCPPortScan -Hosts google.com -Ports 21,22,80,443,8080 -Verbose True 
VERBOSE: +-------------- LIVE RESULTS -------------------+
VERBOSE: 142.250.186.206 (google.com) - port 443 open.
VERBOSE: 142.250.186.206 (google.com) - port 80 open.
VERBOSE: +-----------------------------------------------+
Task finished at 12/19/2023 09:45:49 and scanning time was: 2 seconds, 42 milliseconds.

PowerNetScan scan results:
Totally scanned 1 hosts.
Did NOT perform ping check.

142.250.186.206 (google.com) open ports:
443
80
-----------
```

```
PS> Invoke-TCPPortScan -HostsFile ./test_scope.txt -Threads 50 -Timeout 0.5 -ObjectOutput -FileOutput results.txt

PowerNetScan started at: 12/19/2023 10:18:28 with command: Invoke-TCPPortScan -HostsFile ./test_scope.txt -Threads 50 -Timeout 0.5 -ObjectOutput True -FileOutput results.txt 
Task finished at 12/19/2023 10:18:48 and scanning time was: 20 seconds, 83 milliseconds.


IPAddress       Hostname      OpenPorts
---------       --------      ---------
20.112.250.133  microsoft.com {443, 80}
20.231.239.246  microsoft.com {80, 443}
20.236.44.162   microsoft.com {80, 443}
20.70.246.20    microsoft.com {443, 80}
20.76.201.171   microsoft.com {443, 80}
205.251.242.103 amazon.com    {80, 443}
216.58.208.206  google.com    {80, 443}
52.94.236.248   amazon.com    {80, 443}
54.239.28.85    amazon.com    {80, 443}
```

```
PS> $results = Invoke-TCPPortScan -Hosts 192.168.88.0/24 -Ports 80 -Threads 50 -Verbose -ObjectOutput

VERBOSE: Parsing input.
VERBOSE: Source of targets - script argument.
VERBOSE: Scan scope summary: 254 hosts / 1 ports.
PowerNetScan started at: 12/19/2023 10:31:59 with command: Invoke-TCPPortScan -Hosts 192.168.88.0/24 -Ports 80 -Threads 50 -Verbose True -ObjectOutput True 
VERBOSE: +-------------- LIVE RESULTS -------------------+
VERBOSE: 192.168.88.183 - port 80 open.
VERBOSE: 192.168.88.2 - port 80 open.
VERBOSE: +-----------------------------------------------+
Task finished at 12/19/2023 10:32:05 and scanning time was: 6 seconds, 96 milliseconds.
```

## Acknowledgments

Thanks a lot! I was inspired by the project https://github.com/BornToBeRoot/PowerShell_IPv4PortScanner/blob/main/Scripts/IPv4PortScan.ps1 in terms of multithreading.

## To Do

I want to add UDP scan functionality. If I will find proper use case I add more formats of file output like JSON or XML. 
There is also idea to add support of IPv6.

## Licence 

Available at LICENCE file. 
