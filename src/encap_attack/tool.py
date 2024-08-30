import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
import click
from encap_attack.utils.encapsulation_models import *
from encap_attack.utils.util_models import *
from typing import Optional

@click.group(context_settings={'max_content_width': 99999})
@click.option("-i", "--iface", type=str, help="Network interface to use", default=None)
@click.option("--ip", type=str, help="Interface IP address", default=None)
@click.option("--verbose/--no-verbose", "-v", type=bool, help="Verbose mode enabled", default=False)
@click.pass_context
def cli(ctx, iface: Optional[str], ip: Optional[str], verbose: bool) -> None:
    """A CLI tool to facilitate communication and tunneling into overlay networks, in particular for penetration testing."""
    
    ctx.ensure_object(dict)
    if iface:
        click.echo(f"Forcing interface: {iface}\n")
    ctx.obj["iface"] = iface
    ctx.obj["iface_ip"] = ip
    ctx.obj["verbose"] = verbose
    if (verbose):
        click.echo("Verbose mode is on")

@cli.command()
@click.option("-t", "--timeout", type=int, help="Sniff timeout in seconds [DEFAULT: None]", default=None)
@click.pass_context
def detect(ctx, timeout: Optional[int]) -> None:
    """Sniff network traffic to identify encapsulated packets."""

    detectEncap(ctx.obj["iface"], timeout, ctx.obj["verbose"])

@cli.group()
def kubeintel():
    """Gain information about a Kubernetes cluster for use in future network encapsulation attacks."""

@kubeintel.command("attempt-ipip")
@click.option("-a", "--api-server", type=str, help="API server IP address or hostname", required=True)
@click.option("-p", "--api-server-port", type=int, help="API server port [DEFAULT: 6443]", default=6443)
@click.option("-d", "--intermediary-dst-ip", type=str, help="Intermediary destination IP - for Kubernetes, use the destination node [DEFAULT: API server address]", default=None)
@click.option("-s", "--spoofed-src-ip", type=str, help="Spoofed packet source IP address [DEFAULT: interface IP]", default=None)
@click.option("-m", "--spoofed-src-mac", type=str, help="Spoofed packet source MAC address [DEFAULT: MAC associated with spoofed source IP (obtained with ARP)]", default=None)
@click.option("-ps", "--src-port", type=int, help="Source port [DEFAULT: random port 1000-65000]", default=None)
@click.option("-pd", "--dst-port", type=int, help="Destination port [DEFAULT: 53]", default=53)
@click.pass_context
def attempt_ipip(ctx, api_server: str, api_server_port: int, intermediary_dst_ip: Optional[str], spoofed_src_ip: Optional[str], spoofed_src_mac: Optional[str], src_port: Optional[int], dst_port: int) -> None:
    """Guess DNS server address based on Kubernetes API server certificate contents, and attempt to connect to it using IP-in-IP"""

    if (not intermediary_dst_ip): intermediary_dst_ip = api_server

    try:
        dns_suffix, _, dns_ip = guessRoutes(api_server, api_server_port)
        if (not dns_ip):
            raise ValueError("Unable to guess DNS server IP. Is the intermediary destination IP correct?")
        model = IPIPEncapsulationModel(intermediary_dst_ip, spoofed_src_ip, spoofed_src_mac, ctx.obj["iface"], ctx.obj["iface_ip"], ctx.obj["verbose"])
        results = model.sendDNS(dns_ip, "kube-dns.kube-system.svc." + dns_suffix, "A", dst_port=dst_port, src_port=src_port)
        if len(results.items()) == 0:
            raise ValueError("Unable to connect to DNS server using IP-in-IP. Try a different intermediary destination IP (another node), a different source IP, or VXLAN?")
        click.secho("\nConnected to DNS server with IP-in-IP", fg="green", bold=True)
    except ValueError as e:
        click.secho(f"\n{e}", fg="red", bold=True)

@kubeintel.command("get-ip-ranges")
def get_ip_ranges() -> None:
    """List commands to obtain pod/service IP ranges from kubectl, via the kube-apiserver."""

    click.echo()
    click.echo("To obtain pod/service IP ranges for a cluster, run the following command(s).")
    click.echo("- Pod CIDR:")
    click.secho("    kubectl cluster-info dump | grep -m 1 cluster-cidr | awk -F= '{print$2}' | awk -F\\\" '{print $1}'", fg="cyan", bold=True)
    click.echo("- Service CIDR:")
    click.secho("    kubectl cluster-info dump | grep -m 1 service-cluster-ip-range | awk -F= '{print$2}' | awk -F\\\" '{print $1}'", fg="cyan", bold=True)
    click.echo()

@kubeintel.command("get-net-info")
@click.option("-c", "--cni", type=click.Choice(["calico", "flannel"]), help="CNI")
def get_net_info(cni: Optional[str]) -> None:
    """List commands to obtain VTEPs and VNIs from different Kubernetes CNIs, via the kube-apiserver."""

    click.echo()
    click.echo("To obtain network info (VNIs and VTEPs - internal destination MAC addresses) for a cluster, run the following command(s).")
    if (cni == "calico" or cni == None):
        cmd_vtep = "kubectl get node -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.spec.vxlanTunnelMACAddr}{\"\\n\"}{end}'"
        click.echo("- Calico VTEP:")
        click.secho(f"    {cmd_vtep}", fg="cyan", bold=True)
        click.echo("- Calico VNI:")
        cmd_vni = "kubectl get felixconfiguration -o jsonpath='{.items[0].spec.vxlanVNI}'"
        click.secho(f"    {cmd_vni}", fg="cyan", bold=True)
    if (cni == "flannel" or cni == None):
        cmd = "kubectl get node -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.metadata.annotations.flannel\.alpha\.coreos\.com/public-ip}{\"\\t\"}{.metadata.annotations.flannel\.alpha\.coreos\.com/backend-data}{\"\\n\"}{end}'"
        click.echo("- Flannel VTEP & VNI:")
        click.secho(f"    {cmd}", fg="cyan", bold=True)
    click.echo()

@kubeintel.command("guess-cidr")
@click.option("-p", "--api-server-port", type=int, help="API server port [DEFAULT: 6443]", default=6443)
@click.argument("api_server")
def guess_cidr(api_server_port: int, api_server: str) -> None:
    """Guess the Kubernetes service IP range based on the certificate from the API server at API_SERVER."""

    click.echo()
    guessRoutes(api_server, api_server_port)
    click.echo()


@cli.group()
@click.option("-d", "--intermediary-dst-ip", type=str, help="Intermediary destination IP - for Kubernetes, use the destination node", required=True)
@click.option("-s", "--spoofed-src-ip", type=str, help="Spoofed packet source IP address [DEFAULT: interface IP]", default=None)
@click.option("-m", "--spoofed-src-mac", type=str, help="Spoofed packet source MAC address [DEFAULT: MAC associated with spoofed source IP (obtained with ARP)]", default=None)
@click.pass_context
def ipip(ctx, intermediary_dst_ip: str, spoofed_src_ip: Optional[str], spoofed_src_mac: Optional[str]) -> None:
    """Suite of IP-in-IP functionality."""

    click.echo("Running in IP-in-IP mode\n")
    ctx.ensure_object(dict)
    ctx.obj["intermediary_dst_ip"] = intermediary_dst_ip
    ctx.obj["spoofed_src_ip"] = spoofed_src_ip
    ctx.obj["spoofed_src_mac"] = spoofed_src_mac
    ctx.obj["model"] = IPIPEncapsulationModel(ctx.obj["intermediary_dst_ip"], ctx.obj["spoofed_src_ip"], ctx.obj["spoofed_src_mac"], ctx.obj["iface"], ctx.obj["iface_ip"], verbose=ctx.obj["verbose"])

@ipip.group("request")
@click.option("-di", "--dst-ip", type=str, help="Internal destination IP - for Kubernetes, use pod/service IP", required=True)
@click.option("-ps", "--src-port", type=int, help="Source port [DEFAULT: random port 1000-65000]", default=None)
@click.pass_context
def ipip_request(ctx, dst_ip: str, src_port: Optional[int]) -> None:
    """Send an IP-in-IP encapsulated request."""

    ctx.ensure_object(dict)
    ctx.obj["dst_ip"] = dst_ip
    ctx.obj["src_port"] = src_port

@ipip_request.command("http")
@click.option("-pd", "--dst-port", type=int, help="Destination port [DEFAULT: 80]", default=80)
@click.argument("http_request")
@click.pass_context
def ipip_http(ctx, dst_port: int, http_request: str) -> None:
    """Send an HTTP request, HTTP_REQUEST, to a client at port DST_PORT."""

    ctx.obj["model"].sendHTTP(http_request, ctx.obj["dst_ip"], dst_port=dst_port, src_port=ctx.obj["src_port"])

@ipip_request.command("dns")
@click.option("-t", "--query-type", type=click.Choice(["SRV", "A", "AAAA", "CNAME"]), help="DNS record query type", required=True)
@click.option("-pd", "--dst-port", type=int, help="Destination port [DEFAULT: 53]", default=53)
@click.argument("query_name")
@click.pass_context
def ipip_dns(ctx, query_type: str, dst_port: int, query_name: str) -> None:
    """Send a DNS request, QUERY_NAME, of type QUERY_NAME."""

    ctx.obj["model"].sendDNS(ctx.obj["dst_ip"], query_name, query_type, dst_port=dst_port, src_port=ctx.obj["src_port"])

@ipip.command("tunnel")
@click.option("-r", "--route", type=str, help="Route to add via tunnel - multiple allowed", multiple=True)
@click.option("-g", "--direct-routing-gateway", type=str, help="Local tunnel gateway IP address to enable routing directly into tunnel interface")
@click.option("-a", "--kube-api-server", type=str, help="Kubernetes API server IP address or hostname - if provided, will attempt to guess Kubernetes service IP range and add it as a route")
@click.option("-p", "--kube-api-server-port", type=int, help="Kubernetes API server port [DEFAULT: 6443]", default=6443)
@click.pass_context
def ipip_tunnel(ctx, route: list[str], direct_routing_gateway: Optional[str], kube_api_server: Optional[str], kube_api_server_port: int) -> None:
    """Open IP-in-IP tunnel via INTERMEDIARY_DESTINATION for each ROUTE."""

    if (kube_api_server):
        click.echo()
        route = list(route)
        route.extend(guessRoutes(kube_api_server, kube_api_server_port)[1])
        click.echo()
    tunnel_meta = TunnelMeta(route, direct_routing_gateway)
    ctx.obj["model"].runTunnel(tunnel_meta)



@cli.group()
@click.option("-d", "--intermediary-dst-ip", type=str, help="Intermediary destination IP - for Kubernetes, use the destination node", required=True)
@click.option("-s", "--spoofed-src-ip", type=str, help="Spoofed packet source IP address [DEFAULT: interface IP]", default=None)
@click.option("-m", "--spoofed-src-mac", type=str, help="Spoofed packet source MAC address [DEFAULT: MAC associated with spoofed source IP (obtained with ARP)]", default=None)
@click.option("-mi", "--inner-dst-mac", type=str, help="Inner destination MAC address (VTEP) - for Kubernetes, use the VTEP of the destination node", required=True)
@click.option("--vni", type=int, help="VXLAN VNI - use 4096 for Calico, 1 for Flannel [DEFAULT: 4096]", default=4096)
@click.option("-ps", "--vxlan-src-port", type=int, help="VXLAN packet source port [DEFAULT: random port 1000-65000]", default=None)
@click.option("-pd", "--vxlan-dst-port", type=int, help="VXLAN packet destination port - use 4789 for Calico, 8472 for Flannel [DEFAULT: 4789]", default=4789)
@click.pass_context
def vxlan(ctx, intermediary_dst_ip: str, spoofed_src_ip: Optional[str], spoofed_src_mac: Optional[str], inner_dst_mac: str, vni: int, vxlan_src_port: Optional[int], vxlan_dst_port: int) -> None:
    """Suite of VXLAN functionality."""

    click.echo("Running in VXLAN mode\n")
    ctx.ensure_object(dict)
    ctx.obj["intermediary_dst_ip"] = intermediary_dst_ip
    ctx.obj["spoofed_src_ip"] = spoofed_src_ip
    ctx.obj["spoofed_src_mac"] = spoofed_src_mac
    ctx.obj["vni"] = vni
    ctx.obj["vxlan_src_port"] = vxlan_src_port
    ctx.obj["vxlan_dst_port"] = vxlan_dst_port
    ctx.obj["model"] = VXLANEncapsulationModel(ctx.obj["intermediary_dst_ip"], inner_dst_mac, vni, vxlan_src_port, vxlan_dst_port, ctx.obj["spoofed_src_ip"], ctx.obj["spoofed_src_mac"], ctx.obj["iface"], ctx.obj["iface_ip"], verbose=ctx.obj["verbose"])

@vxlan.group("request")
@click.option("-di", "--dst-ip", type=str, help="Internal destination IP - for Kubernetes, use pod/service IP", required=True)
@click.option("-ps", "--src-port", type=int, help="Source port [DEFAULT: random port 1000-65000]", default=None)
@click.pass_context
def vxlan_request(ctx, dst_ip: str, src_port: Optional[int]) -> None:
    """Send a VXLAN encapsulated request."""

    ctx.ensure_object(dict)
    ctx.obj["dst_ip"] = dst_ip
    ctx.obj["src_port"] = src_port

@vxlan_request.command("http")
@click.option("-pd", "--dst-port", type=int, help="Destination port [DEFAULT: 80]", default=80)
@click.argument("http_request")
@click.pass_context
def vxlan_http(ctx, dst_port: int, http_request: str) -> None:
    """Send an HTTP request, HTTP_REQUEST, to a client at port DST_PORT."""
    
    ctx.obj["model"].sendHTTP(http_request, ctx.obj["dst_ip"], dst_port=dst_port, src_port=ctx.obj["src_port"])

@vxlan_request.command("dns")
@click.option("-t", "--query-type", type=click.Choice(["SRV", "A", "AAAA", "CNAME"]), help="DNS record query type", required=True)
@click.option("-pd", "--dst-port", type=int, help="Destination port [DEFAULT: 53]", default=53)
@click.argument("query_name")
@click.pass_context
def vxlan_dns(ctx, query_type: str, dst_port: int, query_name: str) -> None:
    """Send a DNS request, QUERY_NAME, of type QUERY_NAME."""

    ctx.obj["model"].sendDNS(ctx.obj["dst_ip"], query_name, query_type, dst_port=dst_port, src_port=ctx.obj["src_port"])

@vxlan.command("tunnel")
@click.option("-r", "--route", type=str, help="Route to add via tunnel - multiple allowed", multiple=True)
@click.option("-g", "--direct-routing-gateway", type=str, help="Local tunnel gateway IP address to enable routing directly into tunnel interface")
@click.option("-a", "--kube-api-server", type=str, help="Kubernetes API server IP address or hostname - if provided, will attempt to guess Kubernetes service IP range and add it as a route")
@click.option("-p", "--kube-api-server-port", type=int, help="Kubernetes API server port [DEFAULT: 6443]", default=6443)
@click.pass_context
def vxlan_tunnel(ctx, route: tuple[str], direct_routing_gateway: Optional[str], kube_api_server: Optional[str], kube_api_server_port: int) -> None:
    """Open VXLAN tunnel via INTERMEDIARY_DESTINATION for each ROUTE."""

    if (kube_api_server):
        route = list(route)
        click.echo()
        _, svc_route, _ = guessRoutes(kube_api_server, kube_api_server_port)
        route.extend(svc_route)
        click.echo()
    tunnel_meta = TunnelMeta(route, direct_routing_gateway)
    ctx.obj["model"].runTunnel(tunnel_meta)

if __name__ == "__main__":
   cli()
