import socket
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url: str) -> bool:
    """
    Checks if a URL is safe to scan.
    - Must be http or https
    - Must have a valid hostname
    - Must not resolve to a private or local IP address (SSRF protection)
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Resolve hostname to IPs (both IPv4 and IPv6)
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip_address = item[4][0]
            ip = ipaddress.ip_address(ip_address)

            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return False

        return True
    except Exception:
        return False
