import hashlib
import json
import urllib3

from .base import DeviceBase


class MagwellDevice(DeviceBase):
    """
    Magwell decoder/encoder.

    Communicates via the Magwell HTTP API at http://{ipAddress}/mwapi.
    Session ID (sid) is obtained at login and stored on the device dict.
    """

    device_type = 'magwell'

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    def login(self) -> bool:
        device   = self.device
        ip       = device.get('ipAddress')
        username = device.get('username')
        password = device.get('password')
        device_id = device.get('deviceId')

        url          = f'http://{ip}/mwapi'
        md5_password = hashlib.md5(password.encode('utf-8')).hexdigest()

        params = {'method': 'login', 'id': username, 'pass': md5_password}
        print(f'\tLogging into Magwell: {url}')

        try:
            http = urllib3.PoolManager(
                timeout=urllib3.Timeout(connect=5.0, read=15.0)
            )
            response = http.request('GET', url, fields=params)
            http.clear()

            if response.status == 200:
                sid = None
                for header, value in response.headers.items():
                    if header.lower() == 'set-cookie':
                        sid = value.split(';')[0].split('=')[1]

                device['sid']    = sid
                device['status'] = 'online'
                print(f'\tMagwell login OK — sid={sid}')
                return True
            else:
                print(f'\tMagwell login failed — HTTP {response.status}')

        except Exception as e:
            print(f'[{device_id}] Magwell connect failed: {e}')

        device['status'] = 'offline'
        return False

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def play(self, message: dict) -> None:
        stream_url  = message.get('streamUrl')
        stream_name = message.get('streamName')

        self.device['streamName'] = stream_name
        self.device['streamUrl']  = stream_url

        tuning     = self.cfg.get('magwellTuning') or {}
        proto      = self._protocol(stream_url)
        url_to_use = self._apply_url_tuning(stream_url, tuning)

        print(f'[magwell] play: protocol={proto!r}')
        print(f'[magwell] play: magwellTuning={tuning}')
        print(f'[magwell] play: url_to_use={url_to_use!r}')
        print(f'[magwell] play: api_tuning_params={self._api_tuning_params(stream_url, tuning)}')

        # add-channel → modify-channel → set-channel
        # All mw-* tuning params are embedded in url_to_use per the Magwell API spec.
        self._send({'method': 'add-channel', 'name': stream_name, 'url': url_to_use})

        self._send({'method': 'modify-channel', 'name': stream_name, 'url': url_to_use})

        set_params = {'method': 'set-channel', 'name': stream_name, 'ndi-name': 'false'}
        print(f'[magwell] set-channel params={set_params}')
        self._send(set_params)

    def stop(self, message: dict) -> None:
        stream_name = self.device.get('streamName')
        self._send({'method': 'clear-channels', 'name': stream_name})

    def status(self, message: dict) -> dict:
        res = self._send({'method': 'get-signal-info'})
        self.device['lastStatus'] = res
        return self.get_status_snapshot()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _protocol(url: str) -> str:
        """Return 'srt', 'rtmp', or 'hls' based on URL scheme."""
        if url.startswith('srt://'):
            return 'srt'
        if url.startswith('rtmp://') or url.startswith('rtmps://'):
            return 'rtmp'
        return 'hls'

    def _apply_url_tuning(self, url: str, tuning: dict) -> str:
        """
        Magwell reads all mw-* params (and SRT params like latency) from the
        URL query string for every protocol — they are NOT standalone API
        parameters.  Append the protocol-specific tuning dict from magwellTuning
        to the URL for all protocols (srt, hls, rtmp).
        """
        proto  = self._protocol(url)
        params = tuning.get(proto, {})
        if not params:
            return url

        separator = '&' if '?' in url else '?'
        extra     = '&'.join(f'{k}={v}' for k, v in params.items())
        return f'{url}{separator}{extra}'

    def _api_tuning_params(self, url: str, tuning: dict) -> dict:
        """
        All tuning params are embedded in the URL (see _apply_url_tuning).
        This method is kept for compatibility but always returns an empty dict.
        """
        return {}

    def _send(self, params: dict, retries: int = 3) -> bool:
        """Send a single Magwell API call; re-login on status 37."""
        device = self.device
        ip     = device.get('ipAddress')
        sid    = device.get('sid')
        url    = f'http://{ip}/mwapi'

        headers = {'Cookie': f'sid={sid}'}
        http    = urllib3.PoolManager(timeout=urllib3.Timeout(connect=6.0, read=6.0))

        for attempt in range(retries):
            response = http.request('GET', url, fields=params, headers=headers)
            if response.status == 200:
                res    = json.loads(response.data.decode('utf-8'))
                status = res.get('status')
                if status == 0:
                    http.clear()
                    return True
                elif status == 37:
                    print('Magwell session expired (37); re-logging in')
                    self.login()
                    headers = {'Cookie': f'sid={device.get("sid")}'}
                else:
                    print(f'Magwell unexpected status {status}: {res}')
            else:
                print(f'Magwell bad HTTP response [{response.status}]')

        http.clear()
        return False
