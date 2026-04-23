import logging
import subprocess
import time
import traceback

from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub, SubscribeListener

from .config import load_config
from .status import StatusReporter
from .devices import DEVICE_REGISTRY
from .tasks  import start_background_task


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PubNub status listener
# ---------------------------------------------------------------------------

class _StatusListener(SubscribeListener):
    def status(self, pubnub, status):
        print(f'PubNub status: {status.category.name}')


# ---------------------------------------------------------------------------
# Device setup
# ---------------------------------------------------------------------------

def setup_devices(cfg: dict, reporter: StatusReporter) -> None:
    """
    Login to every device in serveDevices, then push an initial status report.
    Unknown device types are logged and treated as 'online' (passthrough).
    """
    serve_devices = cfg.get('serveDevices', {})

    for device_id, device in serve_devices.items():
        device_type = device.get('deviceType')
        device_name = device.get('deviceName', device_id)
        print(f'Setting up device: {device_name} ({device_type})')

        device_cls = DEVICE_REGISTRY.get(device_type)
        if device_cls:
            instance = device_cls(cfg, device)
            instance.login()
        else:
            print(f'  Unknown deviceType "{device_type}" — marking online')
            device['status'] = 'online'

    reporter.push_devices(serve_devices)


# ---------------------------------------------------------------------------
# Message processing
# ---------------------------------------------------------------------------

def process_message(state: dict, message: dict, reporter: StatusReporter,
                    log) -> None:
    """
    Dispatch a single PubNub message.

    state is {'cfg': cfg} so that a 'refresh' command can replace the cfg
    dict and have subsequent messages see the updated version.
    log is the MsgLocalLogger instance passed from the entrypoint.
    """
    send_log = True
    log.reset()
    log.set('success', True)
    log.set('log_type', 'control_message')
    log.set('message', message)
    print(f'Message received: {message}')

    try:
        cfg     = state['cfg']
        command = message.get('command')

        valid_commands = {'refresh', 'update', 'play', 'stop', 'status', 'dial', 'hangup',
                          'reconnect_proxy'}
        if command not in valid_commands:
            from includes.exceptions import InvalidDataError
            raise InvalidDataError(f'Invalid command: {command}')

        # ------------------------------------------------------------------
        # Agent-scoped commands
        # ------------------------------------------------------------------
        if command in ('refresh', 'update', 'reconnect_proxy'):
            agent_id       = message.get('agentId')
            local_agent_id = cfg.get('agentId')
            if agent_id != local_agent_id:
                print(f'{command} for {agent_id} — not for this agent ({local_agent_id})')
                _ignore(log)
                send_log = False
                return

            if command == 'refresh':
                print('Refresh command — reloading config')
                new_cfg    = load_config(cfg)
                state['cfg'] = new_cfg
                reporter.__init__(new_cfg)
                setup_devices(new_cfg, reporter)
                log.set('command_status', 'refresh complete')
                print('Refresh complete')
                return

            if command == 'update':
                log.set('command_status', 'update initiated')
                _execute_update()
                return

            if command == 'reconnect_proxy':
                proxy_cfg = cfg.get('clearcomProxy') or {}
                if proxy_cfg.get('enabled') and proxy_cfg.get('agentId') == local_agent_id:
                    print('reconnect_proxy — restarting ClearCom proxy')
                    from .proxy import restart_proxy_server
                    restart_proxy_server(state, reporter)
                    log.set('command_status', 'proxy restarted')
                else:
                    print('reconnect_proxy — not the designated proxy agent, ignoring')
                    log.set('command_status', 'skipped — not the designated proxy agent')
                return

        # ------------------------------------------------------------------
        # Device-scoped commands
        # ------------------------------------------------------------------
        device_id     = message.get('deviceId')
        serve_devices = cfg.get('serveDevices', {})
        device        = serve_devices.get(device_id)

        if not device:
            print(f'Device [{device_id}] not registered on this agent')
            _ignore(log)
            send_log = False
            return

        device_type = device.get('deviceType')
        log.set('device_id',   device_id)
        log.set('device_type', device_type)

        device_cls = DEVICE_REGISTRY.get(device_type)
        if not device_cls:
            from includes.exceptions import InvalidDataError
            raise InvalidDataError(f'No handler for deviceType "{device_type}"')

        instance = device_cls(cfg, device)
        instance.execute(command, message)

        # Push updated status after any state-changing command
        if command in ('play', 'stop'):
            reporter.push_devices(serve_devices)

    except Exception as exc:
        from includes.exceptions import IgnoreMessageException
        if isinstance(exc, IgnoreMessageException):
            _ignore(log)
            send_log = False
            return

        log.set('success', False)
        trace = traceback.format_exc()
        log.set('EXCEPTION',       str(exc))
        log.set('EXCEPTION_TRACE', trace)
        print(f'process_message error: {exc}\n{trace}')

    finally:
        if send_log:
            log.send()


def _ignore(log) -> None:
    log.reset()


# ---------------------------------------------------------------------------
# Agent update
# ---------------------------------------------------------------------------

def _execute_update() -> None:
    """Run the on-prem update script."""
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO)
    _logger = _logging.getLogger(__name__)

    script = '/opt/noc-agent/update.sh'
    try:
        result = subprocess.run(
            [script, '--silent'],
            check=True, capture_output=True, text=True, cwd='/opt/noc-agent'
        )
        _logger.info(f'Update stdout: {result.stdout.strip()}')
        if result.stderr:
            _logger.warning(f'Update stderr: {result.stderr.strip()}')
        _logger.info('Update initiated')
    except subprocess.CalledProcessError as exc:
        _logger.error(f'Update failed (code {exc.returncode}): {exc.stderr}')
    except FileNotFoundError:
        _logger.error(f'update.sh not found at {script}')


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(cfg: dict, log, version: str) -> None:
    """
    Configure PubNub, set up devices, then subscribe and block forever.
    """
    reporter = StatusReporter(cfg)

    # Initial device setup + heartbeat
    setup_devices(cfg, reporter)
    reporter.push_heartbeat(version, cfg.get('serveDevices', {}))

    # state dict lets process_message update cfg in-place on refresh
    state = {'cfg': cfg}

    # ------------------------------------------------------------------
    # Background tasks
    # ------------------------------------------------------------------

    # ClearCom integration — two mutually-exclusive paths.
    #
    # NEW (preferred, set clearcomProxy.enabled: true):
    #   ONE designated agent (clearcomProxy.agentId == my agentId) runs an
    #   in-process HTTP(S) proxy.  The browser calls the proxy, which holds
    #   a single admin JWT in memory and handles 401 recovery transparently.
    #   Other agents do nothing on ClearCom — avoids session collisions.
    #   The proxy also pushes each freshly acquired token to AWS so any UI
    #   still on the legacy path keeps working during rollout.
    #
    # LEGACY (clearcomProxy.enabled false/missing):
    #   A background task logs in every tokenRefreshSecs seconds and pushes
    #   the JWT to AWS.  Browser reads it via dialer_get_token and calls
    #   ClearCom directly.  Vulnerable to session collisions when multiple
    #   agents or browsers are active at once.
    clearcom_cfg   = cfg.get('clearcomDialer') or {}
    proxy_cfg      = cfg.get('clearcomProxy')  or {}
    local_agent_id = cfg.get('agentId', '')
    proxy_agent_id = proxy_cfg.get('agentId', '')

    if proxy_cfg.get('enabled'):
        if not proxy_agent_id:
            print('[clearcom] REFUSING to start proxy: clearcomProxy.enabled=true '
                  'but clearcomProxy.agentId is empty. Set it to exactly one '
                  "agent's agentId to avoid multi-agent session collisions. "
                  'No ClearCom activity will run on this agent.')
        elif proxy_agent_id != local_agent_id:
            print(f'[clearcom] not the designated proxy agent '
                  f'(local={local_agent_id!r}, designated={proxy_agent_id!r}) '
                  f'— no ClearCom activity on this agent.')
        else:
            print(f'[clearcom] this agent ({local_agent_id!r}) IS the designated '
                  f'proxy — starting proxy thread.')
            from .proxy import start_proxy_server
            start_proxy_server(state, reporter)
    elif clearcom_cfg:
        interval = clearcom_cfg.get('tokenRefreshSecs', 1200)
        from .devices.clearcom import get_token as _cc_get_token

        def _clearcom_token_refresh():
            token = _cc_get_token(state['cfg'])
            if token:
                reporter.push_clearcom_token(token)
            else:
                print('[tasks] ClearCom token refresh failed — skipping push')

        start_background_task(_clearcom_token_refresh, interval,
                              name='clearcom-token-refresh')

    pn_cfg = cfg.get('pubnubConfig', {})
    pnconfig = PNConfiguration()
    pnconfig.subscribe_key  = pn_cfg.get('subscribeKey')
    pnconfig.publish_key    = pn_cfg.get('publishKey')
    pnconfig.user_id        = cfg.get('agentId')
    pnconfig.enable_subscribe = True

    pubnub = PubNub(pnconfig)
    pubnub.add_listener(_StatusListener())

    stack   = cfg.get('stack')
    channel = pn_cfg.get('controlChannelId') or f'{stack}-pnchannel'

    subscription = pubnub.channel(channel).subscription()
    subscription.on_message = lambda msg: process_message(
        state, msg.message, reporter, log
    )
    subscription.subscribe()
    print(f'Subscribed to channel: {channel}')

    # Periodic heartbeat every 5 minutes
    heartbeat_interval = 300
    last_heartbeat     = time.time()

    while True:
        time.sleep(5)
        if time.time() - last_heartbeat >= heartbeat_interval:
            reporter.push_heartbeat(version, state['cfg'].get('serveDevices', {}))
            last_heartbeat = time.time()
