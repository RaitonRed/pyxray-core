import re
import base64
import json
from urllib.parse import urlparse, parse_qs, unquote
from .exceptions import InvalidConfigError

def validate_link(link: str) -> dict:
    """Validate and parse all supported proxy links with strict security checks"""
    protocols = {
        "vmess": _parse_vmess,
        "vless": _parse_vless,
        "trojan": _parse_trojan,
        "reality": _parse_reality
    }
    
    # Basic protocol validation
    protocol = next((p for p in protocols if link.startswith(f"{p}://")), None)
    if not protocol:
        raise InvalidConfigError(f"Unsupported protocol: {link.split('://')[0]}")
    
    # Security: Prevent overly long links
    if len(link) > 2048:
        raise InvalidConfigError("Link exceeds maximum allowed length (2048 chars)")
    
    return protocols[protocol](link)

def _parse_vmess(link: str) -> dict:
    """Parse and validate VMess links"""
    try:
        # Extract base64 part (ignore # fragment)
        b64_data = link[8:].split('#')[0].split('?')[0]
        
        # Security: Check base64 length
        if len(b64_data) < 10 or len(b64_data) > 1024:
            raise ValueError("Invalid base64 length")
        
        # Decode with padding correction
        decoded = base64.b64decode(b64_data + '=' * (-len(b64_data) % 4)).decode('utf-8')
        
        # Security: Prevent JSON bombs
        if len(decoded) > 1024:
            raise ValueError("Decoded data too large")
        
        config = json.loads(decoded)
        
        # Validate required fields
        required = ["v", "add", "port", "id"]
        if not all(key in config for key in required):
            raise ValueError("Missing required VMess fields")
        
        # Validate UUID format
        if not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", config["id"], re.I):
            raise ValueError("Invalid UUID format")
        
        # Convert port to int
        config["port"] = int(config["port"])
        
        # Security: Validate port range
        if not (1 <= config["port"] <= 65535):
            raise ValueError("Port out of range")
        
        # Validate version
        if config.get("v") != "2":
            raise ValueError("Unsupported VMess version")
            
        return {
            "protocol": "vmess",
            "address": config["add"],
            "port": config["port"],
            "id": config["id"],
            "security": config.get("tls", ""),
            "type": config.get("type", "tcp"),
            "host": config.get("host", "")
        }
    
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise InvalidConfigError(f"Invalid VMess link: {str(e)}")

def _parse_vless(link: str) -> dict:
    """Parse and validate VLESS links"""
    try:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        
        # Extract components
        uuid = parsed.username
        address = parsed.hostname
        port = int(parsed.port) if parsed.port else 443
        
        # Security: Validate UUID
        if not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", uuid, re.I):
            raise ValueError("Invalid UUID format")
        
        # Security: Validate port
        if not (1 <= port <= 65535):
            raise ValueError("Port out of range")
        
        # Security: Validate flow (if present)
        flow = query.get("flow", [""])[0]
        if flow and not re.match(r"^[a-zA-Z0-9\-_]+$", flow):
            raise ValueError("Invalid flow parameter")
        
        return {
            "protocol": "vless",
            "address": address,
            "port": port,
            "id": uuid,
            "flow": flow,
            "security": query.get("security", ["tls"])[0],
            "type": query.get("type", ["tcp"])[0],
            "sni": query.get("sni", [""])[0]
        }
    
    except (ValueError, AttributeError) as e:
        raise InvalidConfigError(f"Invalid VLESS link: {str(e)}")

def _parse_trojan(link: str) -> dict:
    """Parse and validate Trojan links"""
    try:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        
        # Security: Validate password length
        password = unquote(parsed.username)
        if len(password) < 4 or len(password) > 100:
            raise ValueError("Invalid password length")
        
        address = parsed.hostname
        port = int(parsed.port) if parsed.port else 443
        
        # Security: Validate port
        if not (1 <= port <= 65535):
            raise ValueError("Port out of range")
        
        # Security: Validate SNI
        sni = query.get("sni", [""])[0]
        if sni and not re.match(r"^[a-zA-Z0-9\.\-]+$", sni):
            raise ValueError("Invalid SNI format")
        
        return {
            "protocol": "trojan",
            "address": address,
            "port": port,
            "password": password,
            "security": query.get("security", ["tls"])[0],
            "sni": sni,
            "type": query.get("type", ["tcp"])[0]
        }
    
    except (ValueError, AttributeError) as e:
        raise InvalidConfigError(f"Invalid Trojan link: {str(e)}")

def _parse_reality(link: str) -> dict:
    """Parse and validate Reality links"""
    try:
        # Extract after reality:// prefix
        config_str = link[10:]
        parts = config_str.split("#")[0].split("?")
        main_part = parts[0]
        query = parse_qs(parts[1]) if len(parts) > 1 else {}
        
        # Split uuid@address:port
        user_info, _, host_port = main_part.partition("@")
        if not user_info or not host_port:
            raise ValueError("Invalid format")
        
        uuid, address_port = user_info, host_port
        address, _, port_str = address_port.partition(":")
        port = int(port_str) if port_str else 443
        
        # Security: Validate UUID
        if not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", uuid, re.I):
            raise ValueError("Invalid UUID format")
        
        # Security: Validate public key
        pbk = query.get("pbk", [""])[0]
        if not re.match(r"^[a-zA-Z0-9+/]{43}=$", pbk):
            raise ValueError("Invalid public key format")
        
        # Security: Validate short ID
        sid = query.get("sid", [""])[0]
        if sid and not re.match(r"^[0-9a-f]{1,16}$", sid, re.I):
            raise ValueError("Invalid short ID format")
        
        return {
            "protocol": "reality",
            "address": address,
            "port": port,
            "id": uuid,
            "pbk": pbk,
            "sni": query.get("sni", [""])[0],
            "sid": sid,
            "spx": query.get("spx", [""])[0],
            "flow": query.get("flow", ["xtls-rprx-vision"])[0]
        }
    
    except (ValueError, IndexError) as e:
        raise InvalidConfigError(f"Invalid Reality link: {str(e)}")