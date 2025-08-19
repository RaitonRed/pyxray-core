import os
import logging
from .exceptions import TunDeviceError

class TunManager:
    def __init__(self, device: str = "tun0", ip: str = "10.0.0.1", netmask: str = "255.255.255.0"):
        self.device = device
        self.ip = ip
        self.netmask = netmask
        self.logger = logging.getLogger("tun_manager")
    
    def create_tun_device(self):
        """Create TUN device (Linux only for now)"""
        try:
            # Create TUN device
            os.system(f"ip tuntap add mode tun dev {self.device}")
            os.system(f"ip addr add {self.ip}/{self.netmask} dev {self.device}")
            os.system(f"ip link set dev {self.device} up")
            self.logger.info(f"TUN device {self.device} created")
            
            # Configure routing
            os.system("sysctl -w net.ipv4.ip_forward=1")
            os.system(f"iptables -t nat -A POSTROUTING -o {self.device} -j MASQUERADE")
        except Exception as e:
            raise TunDeviceError(f"TUN setup failed: {str(e)}")
    
    def cleanup(self):
        """Clean up TUN device"""
        try:
            os.system(f"ip link del dev {self.device}")
            self.logger.info(f"TUN device {self.device} removed")
        except Exception:
            pass