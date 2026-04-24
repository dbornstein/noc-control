import subprocess
import time
import urllib3

from .base import DeviceBase


class VlcDevice(DeviceBase):
    """
    VLC media player controlled via its built-in HTTP interface.

    All VLC-specific settings are read from the device record (self.device),
    not from the top-level agent config (self.cfg).  They are stored on the
    device row in DynamoDB and delivered inside serveDevices.

    Config keys (on the device record):
        vlcHostname   — hostname or IP of the VLC instance (default 'localhost')
        vlcPort       — HTTP interface port (default 8080)
        vlcPassword   — HTTP interface password (default '')
        vlcAutostart  — bool; start VLC subprocess if not already running
        vlcStartDelay — seconds to wait after starting VLC before issuing commands
        vlcCommand    — path to VLC binary (default 'vlc')
        vlcEnabled    — master switch; commands are ignored when False
    """

    device_type = 'vlc'

    def _vlc(self, key, default=None):
        """Read a VLC setting from the device record."""
        return self.device.get(key, default)

    def login(self) -> bool:
        if not self._vlc('vlcEnabled'):
            print('VLC not enabled on device record — skipping')
            self.device['status'] = 'disabled'
            return False
        self.device['status'] = 'online'
        return True

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def play(self, message: dict) -> None:
        if not self._vlc('vlcEnabled'):
            print('VLC not enabled on device record — ignoring play command')
            return

        stream_url = message.get('streamUrl') or ''
        hostname   = self._vlc('vlcHostname', 'localhost') or 'localhost'

        if hostname in ('localhost', '127.0.0.1'):
            self._ensure_running()

        self._send_command('in_play', input_url=stream_url)
        self._send_command('pl_play')

    def stop(self, message: dict) -> None:
        if not self._vlc('vlcEnabled'):
            return
        self._send_command('pl_stop')

    def status(self, message: dict) -> dict:
        return self.get_status_snapshot()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_command(self, command: str, input_url: str | None = None) -> None:
        hostname = self._vlc('vlcHostname', 'localhost') or 'localhost'
        port     = int(self._vlc('vlcPort', 8080) or 8080)
        password = self._vlc('vlcPassword', '') or ''

        http    = urllib3.PoolManager()
        headers = urllib3.util.make_headers(basic_auth=f':{password}')

        query = f'command={command}'
        if input_url:
            query += f'&input={input_url}'

        url      = f'http://{hostname}:{port}/requests/status.xml?{query}'
        response = http.request('GET', url, headers=headers)
        http.clear()

        if response.status != 200:
            print(f'VLC command "{command}" failed — HTTP {response.status}')

    def _ensure_running(self) -> None:
        """Start a VLC subprocess if vlcAutostart is set and VLC isn't running."""
        if not self._vlc('vlcAutostart') or self.device.get('_vlc_running'):
            return

        self.device['_vlc_running'] = True

        port     = int(self._vlc('vlcPort', 8080) or 8080)
        password = self._vlc('vlcPassword', '') or ''
        delay    = float(self._vlc('vlcStartDelay', 2) or 2)
        binary   = self._vlc('vlcCommand', 'vlc') or 'vlc'

        cmd = [
            binary,
            '--extraintf', 'http',
            '--http-port', str(port),
            '--http-password', str(password),
            '--no-playlist-autostart',
            '--no-video-title-show',
        ]
        print(f'Starting VLC: {cmd}')
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f'VLC started with pid {process.pid}; waiting {delay}s')
        time.sleep(delay)
        if process.poll() is not None:
            print(f'VLC process exited early with status {process.poll()}')
