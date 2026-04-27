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
        url_to_use = self._apply_url_tuning(stream_url, tuning)

        # add-channel → modify-channel → set-channel
        add_params = {'method': 'add-channel', 'name': stream_name, 'url': url_to_use}
        add_params.update(self._api_tuning_params(stream_url, tuning))
        self._send(add_params)

        modify_params = {'method': 'modify-channel', 'name': stream_name}
        modify_params.update(self._api_tuning_params(stream_url, tuning))
        self._send(modify_params)

        self._send({'method': 'set-channel', 'name': stream_name, 'ndi-name': 'false'})

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
        For SRT streams the Magwell device reads mw-* params directly from
        the URL string, so we append them there.
        For HLS/RTMP they are passed as separate API params (see _api_tuning_params),
        so the URL is returned unchanged.
        """
        proto = self._protocol(url)
        if proto != 'srt':
            return url

        srt_params = tuning.get('srt', {})
        if not srt_params:
            return url

        separator  = '&' if '?' in url else '?'
        extra      = '&'.join(f'{k}={v}' for k, v in srt_params.items())
        return f'{url}{separator}{extra}'

    def _api_tuning_params(self, url: str, tuning: dict) -> dict:
        """
        For HLS streams, return tuning params to be included as extra keys in
        the Magwell API call (add-channel / modify-channel).
        For SRT/RTMP those params live in the URL, so return an empty dict.
        """
        proto = self._protocol(url)
        if proto == 'hls':
            return dict(tuning.get('hls', {}))
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
