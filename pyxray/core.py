import asyncio
import logging
import json
import tempfile
import os
from .validator import validate_link
from .xray_manager import XrayController
from .dns_resolver import DoHResolver
from .tun_controller import TunManager
from .exceptions import InvalidConfigError, TunDeviceError

class PyXrayCore:
    def __init__(self):
        self.config = None
        self.xray = None
        self.tun_manager = None
        self.dns_resolver = None
        self.logger = logging.getLogger("pyxray_core")
        self.config_file = None

    def config(self, link: str, tun: bool = True, dns_mode: str = "doh"):
        """Configure proxy settings"""
        # Validate and parse link
        self.config = validate_link(link)
        
        # DNS configuration
        if dns_mode == "doh":
            self.dns_resolver = DoHResolver()
        elif dns_mode not in ("system", "none"):
            raise InvalidConfigError(f"Unsupported DNS mode: {dns_mode}")
        
        # TUN configuration
        if tun:
            self.tun_manager = TunManager()
            try:
                self.tun_manager.create_tun_device()
            except Exception as e:
                raise TunDeviceError(f"TUN creation failed: {str(e)}")
        
        # Prepare Xray config
        self._generate_xray_config()

    def _generate_xray_config(self):
        """Generate Xray configuration file"""
        base_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "protocol": "dokodemo-door",
                "listen": "127.0.0.1",
                "port": 1080,
                "settings": {"network": "tcp,udp"}
            }],
            "outbounds": [self._build_outbound()]
        }
        
        # Save to temp file
        self.config_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        with open(self.config_file.name, 'w') as f:
            json.dump(base_config, f)
        self.logger.info(f"Config generated: {self.config_file.name}")

    def _build_outbound(self) -> dict:
        """Build outbound configuration based on protocol"""
        # Simplified example for VMess
        if "v" in self.config:  # VMess identifier
            return {
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": self.config["add"],
                    "port": self.config["port"],
                    "users": [{"id": self.config["id"]}]
                }]}
            }
        # TODO: Add other protocols
        raise InvalidConfigError("Protocol not implemented")

    def run_proxy(self):
        """Run the proxy service"""
        if not self.config_file:
            raise RuntimeError("Configuration not initialized")
        
        self.xray = XrayController(self.config_file.name)
        try:
            self.xray.start()
            self.logger.info("Xray proxy started")
            # Keep main thread alive
            while self.xray.running:
                asyncio.sleep(1)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.logger.error(f"Proxy failed: {str(e)}")
            self.stop()

    def stop(self):
        """Stop all services"""
        if self.xray:
            self.xray.stop()
        if self.tun_manager:
            self.tun_manager.cleanup()
        if self.config_file:
            os.unlink(self.config_file.name)
        self.logger.info("All services stopped")