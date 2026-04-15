import json
import time
import urllib3


class StatusReporter:
    """
    Pushes device status snapshots and agent heartbeats to the control Lambda.

    Endpoints used:
        POST {controlEndpoint}/update_device_status  — per-device status
        POST {controlEndpoint}/agent_heartbeat        — agent health / version
    """

    def __init__(self, cfg: dict):
        self._cfg    = cfg
        self._apikey = cfg.get('localConfig', {}).get('apiKey', '')

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def push_devices(self, devices: dict) -> None:
        """
        POST current device status for all devices in the supplied dict.

        devices: the serveDevices dict {deviceId: deviceRecord}
        """
        config_id = self._cfg.get('configId') or self._cfg.get('localConfig', {}).get('configId')
        endpoint  = self._cfg.get('controlEndpoint', '')

        if not endpoint:
            print('StatusReporter: controlEndpoint not configured — skipping push')
            return

        url = endpoint.format(configId=config_id, operation='update_device_status')
        payload = {deviceId: {
            'deviceId':    deviceId,
            'status':      rec.get('status', 'unknown'),
            'streamName':  rec.get('streamName'),
            'deviceType':  rec.get('deviceType'),
            'lastUpdated': int(time.time()),
        } for deviceId, rec in devices.items()}

        self._post(url, payload)

    def push_heartbeat(self, version: str, devices: dict) -> None:
        """
        POST an agent heartbeat with version and per-device summary.

        Called on startup and periodically by the loop.
        """
        config_id  = self._cfg.get('configId') or self._cfg.get('localConfig', {}).get('configId')
        agent_id   = self._cfg.get('agentId')
        endpoint   = self._cfg.get('controlEndpoint', '')

        if not endpoint:
            print('StatusReporter: controlEndpoint not configured — skipping heartbeat')
            return

        url = endpoint.format(configId=config_id, operation='agent_heartbeat')

        device_summary = [{
            'deviceId':   did,
            'deviceName': rec.get('deviceName'),
            'deviceType': rec.get('deviceType'),
            'status':     rec.get('status', 'unknown'),
        } for did, rec in devices.items()]

        payload = {
            'agentId':       agent_id,
            'version':       version,
            'timestamp':     int(time.time()),
            'device_summary': device_summary,
        }
        self._post(url, payload)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _post(self, url: str, payload: dict) -> None:
        body    = json.dumps(payload).encode('utf-8')
        headers = {'x-api-key': self._apikey, 'Content-Type': 'application/json'}
        http    = urllib3.PoolManager(timeout=urllib3.Timeout(connect=5.0, read=10.0))
        try:
            response = http.request('POST', url, body=body, headers=headers)
            if response.status != 200:
                print(f'StatusReporter POST failed [{response.status}]: {url}')
        except Exception as e:
            print(f'StatusReporter POST exception: {e}')
        finally:
            http.clear()
