import json
import time
import datetime
from traceback import extract_stack

from iam_role_anywhere import IamAnywhere
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Base logger (used by Lambda functions)
# ---------------------------------------------------------------------------

class MsgLogger:
    """Lightweight structured logger that accumulates key/value pairs and
    emits them as a single JSON message via send()."""

    def __init__(self):
        self._logs             = {}
        self._skip_on_success  = False
        self._event            = {}

    def clear(self, event={}):
        self.reset(event)

    def skip_on_success(self):
        self._skip_on_success = True

    def reset(self, event={}):
        self._logs            = {}
        self._event           = event
        self._skip_on_success = False

    def set(self, key, value):
        self._logs[key] = value

    def get(self, key):
        return self._logs.get(key)

    def log(self, msg, suppressLocal=False):
        if suppressLocal and self._event.get('configData', {}).get('local'):
            return
        print(msg)

    def fetch(self):
        return self._logs

    def send(self, suppressLocal=False):
        self.set('event', self._event)
        cfg         = self._logs.get('config', {})
        filter_keys = cfg.get('lambdaLogging', {}).get('successFilterKeys', [])
        success     = self._logs.get('success', False)

        if self._skip_on_success and success:
            return

        if success:
            logs = self._logs.copy()
            for key in list(logs.keys()):
                if 'EXCEPTION' in key:
                    self._logs.pop(key, None)
            for key in filter_keys:
                self._logs.pop(key, None)

        if suppressLocal and self._event.get('configData', {}).get('local'):
            return

        self.send_message(json.dumps(self._logs, default=str))

    def send_message(self, msg):
        print(msg)


# ---------------------------------------------------------------------------
# Local logger — used by the noc-agent (logs to CloudWatch via IAM Anywhere)
# ---------------------------------------------------------------------------

class MsgLocalLogger(MsgLogger):
    """Extends MsgLogger to push log messages to CloudWatch via IAM Roles Anywhere."""

    def __init__(self, cfg={}):
        super().__init__()
        self._cfg = cfg
        al_cfg    = cfg.get('localLogging', {})
        self._region    = cfg.get('region')
        self._cw_group  = al_cfg.get('cwGroupName')
        self._cw_stream = al_cfg.get('cwStreamName', '').format(**cfg)
        self._cw_logger = CloudWatchLogger(cfg, self._cw_group, self._cw_stream, self._region)

    def send_message(self, message):
        self._cw_logger.log(message)


# ---------------------------------------------------------------------------
# CloudWatch sink
# ---------------------------------------------------------------------------

class CloudWatchLogger:
    """Writes log events to a CloudWatch log group/stream, rotating streams daily."""

    def __init__(self, cfg, log_group, stream_prefix, region):
        self._cfg            = cfg
        self.log_group       = log_group
        self.stream_prefix   = stream_prefix
        self._current_stream = None
        self._seq_token      = None
        self._current_date   = None

        self._iam = IamAnywhere(cfg, ['logs'])
        self._ensure_log_group()

    def _today_stream_name(self):
        today = datetime.date.today().isoformat()
        return f'[{today}]-{self.stream_prefix}', today

    def _ensure_log_group(self):
        _, clients = self._iam.get_session_and_clients()
        client     = clients.get('logs')
        try:
            client.create_log_group(logGroupName=self.log_group)
        except client.exceptions.ResourceAlreadyExistsException:
            pass

    def _ensure_stream_and_token(self, client):
        stream, day = self._today_stream_name()
        if day != self._current_date:
            self._current_stream = None
            self._seq_token      = None
            self._current_date   = day

        if self._current_stream is None:
            try:
                client.create_log_stream(logGroupName=self.log_group, logStreamName=stream)
                self._seq_token = None
            except client.exceptions.ResourceAlreadyExistsException:
                desc    = client.describe_log_streams(
                    logGroupName=self.log_group,
                    logStreamNamePrefix=stream,
                    limit=1
                )
                streams = desc.get('logStreams', [])
                if streams:
                    self._seq_token = streams[0].get('uploadSequenceToken')
            self._current_stream = stream

    def log(self, message):
        _, clients = self._iam.get_session_and_clients()
        client     = clients.get('logs')

        self._ensure_stream_and_token(client)
        ts_ms = int(time.time() * 1000)
        args  = {
            'logGroupName':  self.log_group,
            'logStreamName': self._current_stream,
            'logEvents':     [{'timestamp': ts_ms, 'message': message}],
        }
        if self._seq_token:
            args['sequenceToken'] = self._seq_token

        try:
            resp            = client.put_log_events(**args)
            self._seq_token = resp.get('nextSequenceToken')
        except client.exceptions.InvalidSequenceTokenException:
            desc    = client.describe_log_streams(
                logGroupName=self.log_group,
                logStreamNamePrefix=self._current_stream,
                limit=1,
            )
            streams         = desc.get('logStreams', [])
            self._seq_token = streams[0].get('uploadSequenceToken') if streams else None
            args.pop('sequenceToken', None)
            if self._seq_token:
                args['sequenceToken'] = self._seq_token
            resp            = client.put_log_events(**args)
            self._seq_token = resp.get('nextSequenceToken')
        except ClientError as exc:
            raise RuntimeError(f'CloudWatch put_log_events failed: {exc}') from exc


LOG = MsgLogger()
