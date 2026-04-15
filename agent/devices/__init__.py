from .magwell  import MagwellDevice
from .vlc      import VlcDevice
from .clearcom import ClearComDevice

# Maps the deviceType string (stored in the devices DynamoDB table) to the
# class that handles it.  To add a new device type, create a new module,
# subclass DeviceBase, and add one entry here — nothing else changes.
DEVICE_REGISTRY: dict = {
    'magwell':  MagwellDevice,
    'vlc':      VlcDevice,
    'clearcom': ClearComDevice,
}
