class PyXrayError(Exception):
    """Base exception for all pyxray errors"""
    pass

class InvalidConfigError(PyXrayError):
    """Invalid proxy configuration"""
    pass

class XrayConnectionError(PyXrayError):
    """Xray core connection failure"""
    pass

class TunDeviceError(PyXrayError):
    """TUN device operation failed"""
    pass