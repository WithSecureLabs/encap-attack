import click
from scapy.all import *
import threading

class TunnelMeta:
    def __init__(self, routes: list[str] = [], direct_routing_gateway_ip: str = None) -> None:
        """Initialise a tunnel metadata model, to store information about a tunnel before it is configured."""

        self.__routes = routes
        self.__direct_routing_gateway_ip = direct_routing_gateway_ip

    @property
    def getRoutes(self) -> list[str]:
        """Get the defined routes."""

        return self.__routes

    @property
    def getDirectRoutingGatewayIP(self) -> str:
        """Get the direct routing gateway IP address."""

        return self.__direct_routing_gateway_ip

class DetectorSniffer:
    def __init__(self, iface: str, timeout: int, verbose: bool) -> None:
        """Initialise a detector sniffer."""

        self.__iface = iface
        self.__timeout = timeout
        self.__verbose = verbose
        self.__protocol = "unknown"
        if (self.__iface):
            if (self.__timeout):
                self.__sniffer = AsyncSniffer(timeout=self.__timeout, prn=self.__packetHandler, iface=self.__iface)
            else:
                self.__sniffer = AsyncSniffer(prn=self.__packetHandler, iface=self.__iface)
        else:
            if (self.__timeout):
                self.__sniffer = AsyncSniffer(timeout=self.__timeout, prn=self.__packetHandler)
            else:
                self.__sniffer = AsyncSniffer(filter="", prn=self.__packetHandler)
    
    def run(self) -> str:
        click.secho("\nListening for encapsulated packets...", fg="magenta", bold=True)
        self.__sniffer.start()
        # ensure inconsequential errors thrown by sniffer are ignored
        threading.excepthook = lambda e: None
        self.__sniffer.join()
        return self.__protocol
    
    def __packetHandler(self, packet) -> None:
        """Process sniffed packets and stop sniffing if encapsulated packet detected."""

        if (VXLAN in packet and IP in packet and Ether in packet[VXLAN] and IP in packet[VXLAN]):
            # packet is VXLAN
            click.secho("\nIdentified VXLAN packet:", bold=True)
            click.echo("    Outer: " + click.style(f"{packet[IP].src} -> {packet[IP].dst}", fg="cyan", bold=True))
            click.echo("    VXLAN: " + click.style(f"VNI: {packet[VXLAN].vni}, VTEP: {packet[VXLAN][Ether].dst}", fg="cyan", bold=True))
            click.echo("    Inner: " + click.style(f"{packet[VXLAN][IP].src} -> {packet[VXLAN][IP].dst}", fg="cyan", bold=True))
            self.__protocol = "VXLAN"
        elif (IP in packet and IP in packet[IP][1:]):
            # packet is IP-in-IP
            click.secho("\nIdentified IP-in-IP packet:", bold=True)
            click.echo("    Outer: " + click.style(f"{packet[IP].src} -> {packet[IP].dst}", fg="cyan", bold=True))
            click.echo("    Inner: " + click.style(f"{packet[IP][1:][IP].src} -> {packet[IP][1:][IP].dst}", fg="cyan", bold=True))
            self.__protocol = "IP-in-IP"
        else:
            return
        if (self.__verbose):
            click.secho("\nFull packet:", fg="magenta", bold=True)
            click.echo(packet.show2(dump=True))
        self.__sniffer.stop()
