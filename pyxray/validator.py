import re
import base64
import json
from urllib.parse import urlparse, parse_qs

def validate_link(link: str) -> dict:
    """Validate and parse proxy link"""
    protocols = ("vmess://", "vless://", "trojan://", "reality://")
    
    if not link.startswith(protocols):
        raise InvalidConfigError(f"Unsupported protocol: {link.split(':')[0]}")
    
    try:
        # VMess/VLESS validation
        if link.startswith(("vmess://", "vless://")):
            b64_data = link[8:].split('#')[0].split('?')[0]
            decoded = base64.b64decode(b64_data + '=' * (-len(b64_data) % 4)).decode()
            return json.loads(decoded)
        
        # Trojan validation
        elif link.startswith("trojan://"):
            parsed = urlparse(link)
            return {
                "password": parsed.username,
                "address": parsed.hostname,
                "port": parsed.port,
                "params": parse_qs(parsed.query)
            }
        
        # TODO: Add Reality validation
        return {}
    
    except (base64.binascii.Error, json.JSONDecodeError, ValueError) as e:
        raise InvalidConfigError(f"Invalid link format: {str(e)}")