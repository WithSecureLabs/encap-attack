import socket, fcntl, struct, ssl, OpenSSL, click, ipaddress
from encap_attack.utils.util_models import *

def getIfaceIp(iface: str) -> str:
    """Get an interface's default IP."""

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', iface[:15].encode())
    )[20:24])

def getDefaultIfaceIp(dst_ip: str) -> str:
    """Get the default interface's IP address for a specific destination IP."""

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((dst_ip, 53))
    ip = s.getsockname()[0]
    s.close()
    return ip

def getCert(dst: str, port: int):
    """Get a certificate and return it in X509 format."""

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        conn = socket.create_connection((dst, port))
    except Exception as e:
        click.secho(f"Unable to connect: {e}", fg="red", bold=True)
        return None
    sock = context.wrap_socket(conn, server_hostname=dst)
    sock.settimeout(20)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ssl.DER_cert_to_PEM_cert(der_cert))

def getCertSANs(cert) -> list[str]:
    """Get a certificate's Subject Alternative Name records."""

    extensions = (cert.get_extension(i) for i in range(cert.get_extension_count()))
    for e in extensions:
        if (e.get_short_name() == b'subjectAltName'):
            return str(e).split(", ")
    return []

def getIPSANs(sans: list[str]) -> list[str]:
    """Get the IP entries from a certificate's Subject Alternative Name records."""

    ip_sans = []
    for san in sans:
        if (san.startswith("IP Address:")):
            ip_sans.append(san.replace("IP Address:", ""))
    return ip_sans

def getDNSSANs(sans: list[str]) -> list[str]:
    """Get the DNS entries from a certificate's Subject Alternative Name records."""

    ip_sans = []
    for san in sans:
        if (san.startswith("DNS")):
            ip_sans.append(san.replace("DNS:", ""))
    return ip_sans

def getCertDetails(cert) -> tuple[str, str, list[str]]:
    """Extract the subject, issuer, and Subject Alternative Names records from an X509 certificate."""

    subject = dict(cert.get_subject().get_components())
    issuer = dict(cert.get_issuer().get_components())
    return (subject, issuer, getCertSANs(cert))

def guessRoutes(dst: str, port: int) -> tuple[str, list[str], str]:
    """Get the TLS certificate from a Kubernetes API server, and use the Subject Alternative Name records of the contained certificate to guess the cluster DNS suffix, service IP range, and DNS server IP address."""

    cert = getCert(dst, port)
    if (cert == None):
        return ("", [], "")
    subject, issuer, sans = getCertDetails(cert)
    click.secho("Kubernetes API server certificate information:", bold=True)
    click.echo("  Subject: " + click.style(subject[b'CN'].decode(), fg="cyan", bold=True))
    click.echo("  Issuer: " + click.style(issuer[b'CN'].decode(), fg="cyan", bold=True))
    ips = getIPSANs(sans)
    click.echo("  IPs: " + click.style(', '.join(ips), fg="cyan", bold=True))
    hostnames = getDNSSANs(sans)
    click.echo("  Hostnames: " + click.style(', '.join(hostnames), fg="cyan", bold=True))
    priv_ips = [ip for ip in ips if ipaddress.ip_address(ip).is_private]
    cluster_dns_suffix, dot_count = ("", 0)
    for hostname in hostnames:
        count = hostname.count(".")
        if count > dot_count:
            try:
                suffix = hostname.split(".", 3)[3]
            except:
                # hostname is not fully-qualified
                continue
            cluster_dns_suffix = suffix
            dot_count = count
    if len(priv_ips) > 0:
        ip_parts = priv_ips[0].split(".")
        guessed_cidr = f"{ip_parts[0]}.{ip_parts[1]}.0.0/12"
        click.echo("\nGuessed service CIDR: " + click.style(guessed_cidr, fg="green", bold=True))
        guessed_dns = f"{ip_parts[0]}.{ip_parts[1]}.0.10"
        click.echo(f"kube-dns DNS server may be available at: " + click.style(f"{guessed_dns}:53", fg="green", bold=True))
        click.echo(f"Cluster DNS suffix: " + click.style(cluster_dns_suffix if cluster_dns_suffix else "unknown", fg="green", bold=True))
        return (cluster_dns_suffix, [guessed_cidr], guessed_dns)
    else:
        click.echo("Unable to guess service CIDR")
        return (cluster_dns_suffix, [], "")

def detectEncap(iface: str, timeout: int, verbose: bool):
    """Sniff network traffic for encapsulated packets and return the encapsulation protocol."""

    detector = DetectorSniffer(iface, timeout, verbose)
    protocol = detector.run()
    
    if (protocol == "unknown"):
        click.secho("\nNo network encapsulation detected", fg="red", bold=True)
    else:
        click.secho(f"\nDetected encapsulation protocol: {protocol}", fg="green", bold=True)
    
