"""
Port & Service Discovery Agent.

Performs network-level reconnaissance:
- Scans common service ports (HTTP, HTTPS, SSH, FTP, DB, etc.)
- Detects publicly exposed databases
- Identifies exposed admin/management interfaces
- Tests common API gateway ports
- Checks for exposed development services (Webpack dev server, Vite, etc.)
"""

from .base import BaseAgent
import asyncio
import aiohttp
from urllib.parse import urlparse


class PortScanAgent(BaseAgent):
    """Network port and service discovery scanner."""

    # Common ports and their service descriptions
    PORTS = [
        # Web
        (80, "HTTP", "Web server"),
        (443, "HTTPS", "Secure web server"),
        (8080, "HTTP-ALT", "Alternative HTTP / Proxy"),
        (8443, "HTTPS-ALT", "Alternative HTTPS"),
        (8888, "HTTP-ALT", "Jupyter / HTTP Alt"),
        (3000, "DEV-SERVER", "Node.js / React / Next.js dev server"),
        (3001, "DEV-SERVER", "Node.js alt dev server"),
        (4200, "ANGULAR-DEV", "Angular dev server"),
        (5173, "VITE-DEV", "Vite dev server"),
        (5174, "VITE-DEV", "Vite dev server alt"),
        (8000, "DJANGO-DEV", "Django/Python dev server"),
        (4000, "DEV-SERVER", "Development server"),
        (9000, "PHP-FPM", "PHP-FPM / SonarQube"),
        
        # Databases
        (5432, "POSTGRESQL", "PostgreSQL database"),
        (3306, "MYSQL", "MySQL database"),
        (27017, "MONGODB", "MongoDB database"),
        (6379, "REDIS", "Redis cache/DB"),
        (11211, "MEMCACHED", "Memcached"),
        (9200, "ELASTICSEARCH", "Elasticsearch"),
        (5984, "COUCHDB", "CouchDB"),
        (1433, "MSSQL", "Microsoft SQL Server"),
        (1521, "ORACLE", "Oracle database"),
        
        # Admin / Management
        (22, "SSH", "SSH remote access"),
        (21, "FTP", "FTP file transfer"),
        (25, "SMTP", "Email server"),
        (53, "DNS", "DNS server"),
        (110, "POP3", "Email (POP3)"),
        (143, "IMAP", "Email (IMAP)"),
        (445, "SMB", "Windows file sharing"),
        (3389, "RDP", "Remote Desktop (Windows)"),
        (5900, "VNC", "VNC Remote Desktop"),
        
        # Message Queues
        (5672, "AMQP", "RabbitMQ"),
        (15672, "RABBITMQ-MGMT", "RabbitMQ Management"),
        (9092, "KAFKA", "Apache Kafka"),
        
        # Misc
        (2375, "DOCKER-API", "Docker API (INSECURE)"),
        (2376, "DOCKER-TLS", "Docker API (TLS)"),
        (8500, "CONSUL", "HashiCorp Consul"),
        (8200, "VAULT", "HashiCorp Vault"),
        (9090, "PROMETHEUS", "Prometheus monitoring"),
        (3100, "GRAFANA-LOKI", "Grafana Loki"),
        (9093, "ALERTMANAGER", "Prometheus Alertmanager"),
        (2181, "ZOOKEEPER", "Apache ZooKeeper"),
    ]

    # Ports that are dangerous when publicly exposed
    CRITICAL_PORTS = {5432, 3306, 27017, 6379, 11211, 9200, 2375, 1433, 1521}
    HIGH_PORTS = {22, 3389, 5900, 21, 15672, 8500, 8200, 9090, 5984}
    DEV_PORTS = {3000, 3001, 4200, 5173, 5174, 8000, 4000, 8888, 9000}

    async def execute(self):
        await self.emit_event("INFO", "🔌 Starting Port & Service Discovery...")
        await self.update_progress(5)
        
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname
        
        if not hostname:
            await self.emit_event("ERROR", "Could not extract hostname from target URL")
            return
        
        await self.emit_event("INFO", f"Scanning {hostname} for open ports and services...")
        
        open_ports = []
        total_ports = len(self.PORTS)
        
        # Scan in batches with semaphore to avoid overwhelming
        sem = asyncio.Semaphore(15)
        
        async def check_port(port, service, description):
            async with sem:
                try:
                    # TCP connect with timeout
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port),
                        timeout=3.0
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return (port, service, description, True)
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return (port, service, description, False)
        
        tasks = [check_port(port, service, desc) for port, service, desc in self.PORTS]
        results = await asyncio.gather(*tasks)
        
        await self.update_progress(60)
        
        for port, service, description, is_open in results:
            if is_open:
                open_ports.append((port, service, description))
                await self.emit_event("INFO", f"🟢 Port {port} ({service}) — OPEN: {description}")
        
        await self.emit_event("INFO", f"Scan complete: {len(open_ports)}/{total_ports} ports open")
        await self.update_progress(70)
        
        # ===== Report findings by severity =====
        
        # Critical: Exposed databases
        critical_open = [(p, s, d) for p, s, d in open_ports if p in self.CRITICAL_PORTS]
        if critical_open:
            for port, service, desc in critical_open:
                await self.report_finding(
                    severity="CRITICAL",
                    title=f"Publicly Exposed {service} on Port {port}",
                    evidence=f"Port {port} ({service} — {desc}) is open and publicly accessible. Database and cache services should NEVER be directly exposed to the internet.",
                    recommendation=f"Immediately restrict port {port} to internal network only. Use firewall rules to block external access. Access {service} through VPN, SSH tunnel, or application-layer proxy only."
                )
        
        # High: Exposed admin services
        high_open = [(p, s, d) for p, s, d in open_ports if p in self.HIGH_PORTS]
        if high_open:
            for port, service, desc in high_open:
                await self.report_finding(
                    severity="HIGH",
                    title=f"Exposed {service} Service on Port {port}",
                    evidence=f"Port {port} ({service} — {desc}) is publicly accessible. Administrative services should be restricted.",
                    recommendation=f"Restrict access to port {port} using firewall rules or security groups. Consider using VPN or IP allowlisting for administrative access."
                )
        
        # Medium: Development servers in production
        dev_open = [(p, s, d) for p, s, d in open_ports if p in self.DEV_PORTS]
        if dev_open:
            for port, service, desc in dev_open:
                # Check if it's actually a dev server
                await self.report_finding(
                    severity="MEDIUM",
                    title=f"Development Server Port Open: {port} ({service})",
                    evidence=f"Port {port} ({desc}) is open. This is commonly used for development servers which may expose debug information, source maps, and include less security hardening.",
                    recommendation=f"If this is a production deployment, ensure port {port} is not running a development server. Use production-configured servers with debug mode disabled."
                )
        
        await self.update_progress(80)
        
        # ===== Phase 2: HTTP service fingerprinting on open ports =====
        await self.emit_event("INFO", "🔍 Phase 2: Fingerprinting HTTP services on open ports...")
        
        http_ports = [p for p, s, d in open_ports if p not in {22, 21, 25, 53, 110, 143, 445, 5432, 3306, 27017, 6379, 11211, 1433, 1521, 2181}]
        
        async with aiohttp.ClientSession() as session:
            for port in http_ports[:10]:  # Limit fingerprinting
                for scheme in ["http", "https"]:
                    try:
                        url = f"{scheme}://{hostname}:{port}/"
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False, allow_redirects=False) as resp:
                            server = resp.headers.get("Server", "Unknown")
                            powered_by = resp.headers.get("X-Powered-By", "")
                            title_match = ""
                            
                            if resp.content_type and "html" in resp.content_type:
                                body = await resp.text()
                                import re
                                title_match_obj = re.search(r"<title[^>]*>(.*?)</title>", body[:5000], re.IGNORECASE | re.DOTALL)
                                if title_match_obj:
                                    title_match = title_match_obj.group(1).strip()[:100]
                            
                            info = f"Server: {server}"
                            if powered_by:
                                info += f", X-Powered-By: {powered_by}"
                            if title_match:
                                info += f", Title: {title_match}"
                            
                            await self.emit_event("INFO", f"  Port {port} ({scheme}): {info}")
                            
                            # Check for exposed management UIs
                            management_indicators = [
                                "phpMyAdmin", "Adminer", "pgAdmin", "MongoDB Compass",
                                "RabbitMQ Management", "Kibana", "Grafana", "Prometheus",
                                "Jenkins", "SonarQube", "Docker", "Portainer",
                                "Consul", "Vault", "Traefik", "Nginx Proxy Manager",
                            ]
                            
                            for indicator in management_indicators:
                                if indicator.lower() in (title_match or "").lower() or indicator.lower() in server.lower():
                                    await self.report_finding(
                                        severity="HIGH",
                                        title=f"Exposed {indicator} on Port {port}",
                                        evidence=f"{indicator} management interface detected at {scheme}://{hostname}:{port}/ (Title: {title_match}, Server: {server})",
                                        recommendation=f"Restrict access to {indicator} behind VPN or authentication. It should not be publicly accessible."
                                    )
                            
                            break  # Found working scheme, skip other
                    except Exception:
                        continue
        
        await self.update_progress(95)
        
        # Summary
        total_findings = len(critical_open) + len(high_open) + len(dev_open)
        
        if not open_ports:
            await self.emit_event("SUCCESS", "✅ No unexpected open ports detected. Good attack surface hygiene!")
        else:
            await self.emit_event("INFO", f"📊 Port scan summary: {len(open_ports)} open ports, {total_findings} security issues")
        
        await self.update_progress(100)
        await self.emit_event("SUCCESS", f"🔌 Port scan complete. Found {len(open_ports)} open ports.")
