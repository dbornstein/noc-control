import subprocess
import time
import urllib3

from .base import DeviceBase


class VlcDevice(DeviceBase):
    """
    VLC media player controlled via its built-in HTTP interface.

    Config keys used:
        vlcHostname   — hostname or IP of the VLC instance
        vlcPort       — HTTP interface port (default 8080)
        vlcPassword   — HTTP interface password
        vlcAutostart  — bool; start VLC subprocess if not already running
        vlcStartDelay — seconds to wait after starting VLC before issuing commands
        vlcCommand    — path to VLC binary (default 'vlc')
        vlcEnabled    — master switch; commands are ignored when False
    """

    device_type = 'vlc'

    def login(self) -> bool:
        if not self.cfg.get('vlcEnabled'):
            print('VLC not enabled in agent config — skipping')
            self.device['status'] = 'disabled'
            return False
        self.device['status'] = 'online'
        return True

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def play(self, message: dict) -> None:
        if not self.cfg.get('vlcEnabled'):
            print('VLC not enabled — ignoring play command')
            return

        stream_url = message.get('streamUrl')
        hostname   = self.cfg.get('vlcHostname', 'localhost')

        if hostname in ('localhost', '127.0.0.1'):
            self._ensure_running()

        self._send_command('in_play', input_url=stream_url)
        self._send_command('pl_play')

    def stop(self, message: dict) -> None:
        if not self.cfg.get('vlcEnabled'):
            return
        self._send_command('pl_stop')

    def status(self, message: dict) -> dict:
        return self.get_status_snapshot()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_command(self, command: str, input_url: str = None) -> None:
        hostname = self.cfg.get('vlcHostname')
        port     = self.cfg.get('vlcPort')
        password = self.cfg.get('vlcPassword')

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
        if not self.cfg.get('vlcAutostart') or self.cfg.get('_vlc_running'):
            return

        self.cfg['_vlc_running'] = True

        port     = self.cfg.get('vlcPort')
        password = self.cfg.get('vlcPassword')
        delay    = self.cfg.get('vlcStartDelay', 2)
        binary   = self.cfg.get('vlcCommand', 'vlc')

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
