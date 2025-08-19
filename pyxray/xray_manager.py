import subprocess
import threading
import os
import json
import logging
from .exceptions import XrayConnectionError

class XrayController:
    def __init__(self, config_path: str):
        self.process = None
        self.config_path = config_path
        self.logger = logging.getLogger("xray_manager")
        self.running = False

    def start(self):
        """Start Xray core process"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Config file missing: {self.config_path}")
        
        try:
            self.process = subprocess.Popen(
                ["./bin/xray", "run", "-config", self.config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            self.running = True
            threading.Thread(target=self._monitor_output, daemon=True).start()
        except Exception as e:
            raise XrayConnectionError(f"Failed to start Xray: {str(e)}")

    def _monitor_output(self):
        """Monitor Xray output"""
        while self.running and self.process.stdout:
            line = self.process.stdout.readline()
            if not line:
                break
            self.logger.info(line.decode().strip())

    def stop(self):
        """Stop Xray core process"""
        if self.process:
            self.running = False
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()