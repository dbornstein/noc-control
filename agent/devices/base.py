from abc import ABC, abstractmethod


class DeviceBase(ABC):
    """
    Abstract base class for all device types managed by the noc-agent.

    Subclasses must declare a class-level `device_type` string and implement
    the play(), stop(), and status() methods.  login() is optional and defaults
    to a no-op (devices that require authentication override it).
    """

    device_type: str = ""

    def __init__(self, cfg: dict, device: dict):
        self.cfg    = cfg
        self.device = device

    # ------------------------------------------------------------------
    # Optional lifecycle hook
    # ------------------------------------------------------------------

    def login(self) -> bool:
        """Authenticate with the device.  Returns True on success."""
        self.device['status'] = 'online'
        return True

    # ------------------------------------------------------------------
    # Command interface — must be implemented by each device class
    # ------------------------------------------------------------------

    @abstractmethod
    def play(self, message: dict) -> None:
        """Start playback / assign a stream to this device."""
        ...

    @abstractmethod
    def stop(self, message: dict) -> None:
        """Stop playback / clear the current stream."""
        ...

    @abstractmethod
    def status(self, message: dict) -> dict:
        """
        Fetch current device status and return a snapshot dict suitable
        for StatusReporter.push_devices().
        """
        ...

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def execute(self, command: str, message: dict) -> None:
        """Dispatch a command string to the appropriate method."""
        dispatch = {
            'play':   self.play,
            'stop':   self.stop,
            'status': self.status,
        }
        handler = dispatch.get(command)
        if handler is None:
            raise ValueError(f'Unknown command "{command}" for device type "{self.device_type}"')
        handler(message)

    def get_status_snapshot(self) -> dict:
        """Return a minimal status dict for heartbeat / status push."""
        return {
            'deviceId':   self.device.get('deviceId'),
            'deviceName': self.device.get('deviceName'),
            'deviceType': self.device_type,
            'status':     self.device.get('status', 'unknown'),
            'streamName': self.device.get('streamName'),
        }
