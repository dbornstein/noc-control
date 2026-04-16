import json
import urllib3

from .base import DeviceBase


# ---------------------------------------------------------------------------
# Module-level helper — usable without a device instance
# ---------------------------------------------------------------------------

def get_token(cfg: dict) -> str:
    """
    Log in to ClearCom and return the JWT string, or '' on failure.

    Used by the background token-refresh task so the UI can fetch a
    pre-authenticated token from AWS instead of logging in directly
    (which has CORS constraints in the browser).
    """
    dialer_cfg = cfg.get('clearcomDialer', {})
    host       = dialer_cfg.get('host', '').rstrip('/')
    username   = dialer_cfg.get('username', 'admin')
    password   = dialer_cfg.get('password', '')

    if not host or not password:
        print('ClearCom get_token: missing host or password in clearcomDialer config')
        return ''

    url  = f'{host}/api/1/auth/login'
    body = json.dumps({'username': username, 'password': password}).encode('utf-8')

    try:
        http     = urllib3.PoolManager(timeout=urllib3.Timeout(connect=5.0, read=10.0))
        response = http.request('POST', url, body=body,
                                headers={'Content-Type': 'application/json'})
        http.clear()

        for header, value in response.headers.items():
            if header.lower() == 'authorization' and value.startswith('Bearer '):
                token = value.split(' ', 1)[1].strip()
                print(f'ClearCom get_token: OK (host={host})')
                return token

        print(f'ClearCom get_token: no JWT in response (HTTP {response.status})')
        return ''
    except Exception as e:
        print(f'ClearCom get_token exception: {e}')
        return ''


class ClearComDevice(DeviceBase):
    """
    ClearCom Skyport SIP dialer, accessed via the ClearCom REST API.

    This device class runs on-prem (via the noc-agent) where the ClearCom
    unit at http://{host} is directly reachable.  It mirrors the browser-side
    logic in DialerControlPage.jsx but without any CORS / proxy constraints.

    Config keys (from clearcomDialer section, merged into agent config):
        clearcomDialer.host     — e.g. "http://10.11.2.7"
        clearcomDialer.username
        clearcomDialer.password

    Device record (in serveDevices / agents table) expected keys:
        portId       — ClearCom SIP port ID
        deviceId     — ClearCom device ID (integer)
        interfaceId  — ClearCom audio interface ID
        phoneNumber  — phone number / SIP URI associated with this TIF
        name         — human-readable label (e.g. "TIF-2910")
    """

    device_type = 'clearcom'

    def __init__(self, cfg: dict, device: dict):
        super().__init__(cfg, device)
        self._token: str = ''
        self._host:  str = ''

    # ------------------------------------------------------------------
    # Login — POST /api/1/auth/login, cache JWT
    # ------------------------------------------------------------------

    def login(self) -> bool:
        token = get_token(self.cfg)
        if token:
            dialer_cfg   = self.cfg.get('clearcomDialer', {})
            self._host   = dialer_cfg.get('host', '').rstrip('/')
            self._token  = token
            self.device['status'] = 'online'
            return True
        self.device['status'] = 'offline'
        return False

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def play(self, message: dict) -> None:
        """Dial out on this TIF port.  message must contain 'uri'."""
        uri         = message.get('uri') or message.get('streamUrl', '')
        port_id     = self.device.get('portId')
        device_id   = self.device.get('deviceId')
        iface_id    = self.device.get('interfaceId')

        if not uri:
            raise ValueError('ClearCom dial: no URI provided in message')

        url  = f'{self._host}/api/1/devices/{device_id}/interfaces/{iface_id}/ports/{port_id}/calls'
        body = json.dumps({'uri': uri}).encode('utf-8')

        response = self._request('POST', url, body=body)
        result   = json.loads(response.data.decode('utf-8'))
        print(f'ClearCom dial {uri} on port {port_id} → call id {result.get("id")}')

        self.device['activeCallId'] = result.get('id')
        self.device['activeCallUri'] = uri

    def stop(self, message: dict) -> None:
        """Hang up the active call on this TIF port."""
        call_id   = message.get('callId') or self.device.get('activeCallId')
        port_id   = self.device.get('portId')
        device_id = self.device.get('deviceId')
        iface_id  = self.device.get('interfaceId')

        if not call_id:
            print(f'ClearCom hangup: no active call on port {port_id}')
            return

        url = (
            f'{self._host}/api/1/devices/{device_id}/interfaces/{iface_id}'
            f'/ports/{port_id}/calls/{call_id}'
        )
        self._request('DELETE', url)
        print(f'ClearCom hung up call {call_id} on port {port_id}')

        self.device.pop('activeCallId', None)
        self.device.pop('activeCallUri', None)

    def status(self, message: dict) -> dict:
        """Fetch current call state for all TIF ports and return a snapshot."""
        url = f'{self._host}/api/1/devices/interfaces/ports/calls'
        try:
            response   = self._request('GET', url)
            calls      = json.loads(response.data.decode('utf-8'))
            active     = [c for c in calls if c.get('portId') == self.device.get('portId')]
            self.device['activeCalls'] = active
        except Exception as e:
            print(f'ClearCom status fetch failed: {e}')

        return self.get_status_snapshot()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request(self, method: str, url: str, body: bytes = None) -> urllib3.HTTPResponse:
        """Make an authenticated request; re-login once on 401."""
        http     = urllib3.PoolManager(timeout=urllib3.Timeout(connect=5.0, read=10.0))
        headers  = {'Authorization': f'Bearer {self._token}', 'Content-Type': 'application/json'}
        response = http.request(method, url, body=body, headers=headers)

        if response.status == 401:
            print('ClearCom: 401 — refreshing token and retrying')
            self.login()
            headers  = {'Authorization': f'Bearer {self._token}', 'Content-Type': 'application/json'}
            response = http.request(method, url, body=body, headers=headers)

        http.clear()

        if response.status not in (200, 201, 204):
            raise Exception(f'ClearCom {method} {url} → HTTP {response.status}: {response.data.decode("utf-8", errors="replace")}')

        return response
