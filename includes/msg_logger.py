import logging
import json
import sys
import time, datetime
from traceback import extract_stack

from pubnub.utils import extend_list
import boto3
from botocore.exceptions import ClientError

from  iam_role_anywhere import IamAnywhere
import base64


# Global VARIABLES (Set at bottom)

class MsgLogger:
    def __init__(self):
        self._logs = {}
        self._skip_on_success = False
        self._db_log_count = 0
        self._event = {}

        # self._logger = logging.getLogger(__name__)
        # if not self._logger.hasHandlers():
        #     logging.basicConfig(level=logging.INFO)

    def clear(self,event={}):
        self.reset(event)

    def skip_on_success(self):
        self._skip_on_success = True

    ''' This should replace clear above'''
    def reset(self,event={}):
        self._logs = {}
        self._event = event
        self._skip_on_success = False
        self._db_log_count = 0

    def set(self, key, value):
        '''Stores a log entry with the specified key and value.'''
        self._logs[key] = value

    def set_db(self, key, value):
        '''
        appends the counter to the key so we can store multiple
        db transactions
        '''
        dblogs = self._logs.get('db_mongo_logs',{})
        self._db_log_count += 1
        key = f'call_{self._db_log_count}'

        db_success = value.get('db_success')
        #dblogs = {}
        dblogs[key] = value
        self._logs['db_mongo_logs'] = dblogs

        self._logs['db_success'] = value.get('db_success')
        # Perculate the 1st DB_EXCEPTIONs to the main lambda
        if not self._logs.get('DB_EXCEPTION'):
            db_ex = value.get('DB_EXCEPTION')
            db_ex_trace = value.get('DB_EXCEPTION_TRACEBACK')
            self.set('DB_EXCEPTION', db_ex)
            self.set('DB_EXCEPTION_TRACEBACK', db_ex_trace)


    def get(self, key):
        '''Retrieves a log entry by key.'''
        return self._logs.get(key, None)

    def log(self, msg, suppressLocal=False):
        '''Sends a log directly to logger'''

        if  suppressLocal and self._event.get('configData',{}).get('local'):
            return
        #self._logger.info(msg)
        print(msg)

    ''' returns the logs of the current session '''
    def fetch(self):
        return self._logs

    def send(self, suppressLocal=False):
        self.set('event', self._event)
        cfg = self._logs.get('config',{})
        filterKeys = cfg.get('lambdaLogging',{}).get('successFilterKeys',[])
        success = self._logs.get('success',False)
        db_success = self._logs.get('db_success',False)

        if self._skip_on_success and success and db_success:
            # skipping
            return

        self.set('db_success',db_success)

        if success and db_success:
            # Filter any EXCEPTION keys are not set.
            logs = self._logs.copy()
            for key in logs:
                if 'EXCEPTION' in key:
                    del self._logs[key]
            # remove successFilterKeys
            for key in filterKeys:
                if key in self._logs:
                    del self._logs[key]

        if  suppressLocal and self._event.get('configData',{}).get('local'):
            return  

        msg = json.dumps(self._logs,default=str)
        self.send_message(msg)

    def send_message(self,msg):
        print(msg)

'''
Child Class of MsgLogger that establishes an IAM Role Anywhere session and Logs to cloudwatch
Used when the service is not running in a lambda function but still wants to log messages to CW.
'''
class MsgLocalLogger(MsgLogger):
    def __init__(self,cfg={}): 
        super().__init__()  
        self._cfg = cfg
        alCfg = self._cfg.get('localLogging')
        self._region = self._cfg.get('region')
        self._cw_group = alCfg.get('cwGroupName')

        # update the stream name by filling in the macros from cfg.
        self._cw_stream = alCfg.get('cwStreamName').format(**self._cfg)
        self._cw_logger = CloudWatchLogger(self._cfg, self._cw_group,self._cw_stream, self._region)

    def send_message(self, message):
        print('MsgLocalLogger:send_message')
        self._cw_logger.log(message)


'''
Class to log to Cloudwatch.  Handles creating the group, streams, and ordertokens
'''
class CloudWatchLogger:
    def __init__(self, cfg, log_group, stream_prefix, region):
        self._cfg = cfg
        self.log_group = log_group
        self.stream_prefix = stream_prefix
        self._current_stream = None
        self._seq_token = None
        self._current_date = None  # YYYY-MM-DD string

        self._iam = IamAnywhere(self._cfg, ['logs']) 
        
        # run this once on initialization
        self._ensure_log_group()

    def _today_stream_name(self):
        today = datetime.date.today().isoformat()  # YYYY-MM-DD
        return f"{self.stream_prefix}-{today}", today

    def _ensure_log_group(self):

        (_, clients) = self._iam.get_session_and_clients()
        client = clients.get('logs')

        try:
            client.create_log_group(logGroupName=self.log_group)
        except client.exceptions.ResourceAlreadyExistsException:
            pass

    def _ensure_stream_and_token(self, client):
        stream, day = self._today_stream_name()
        # Rotate if date changed
        if day != self._current_date:
            self._current_stream = None
            self._seq_token = None
            self._current_date = day

        if self._current_stream is None:
            # Ensure stream exists
            try:
                client.create_log_stream(
                    logGroupName=self.log_group, logStreamName=stream
                )
                self._seq_token = None
            except client.exceptions.ResourceAlreadyExistsException:
                # Get current token if stream already exists
                desc = client.describe_log_streams(
                    logGroupName=self.log_group, logStreamNamePrefix=stream, limit=1
                )
                streams = desc.get("logStreams", [])
                if streams:
                    self._seq_token = streams[0].get("uploadSequenceToken")
            self._current_stream = stream


    def log(self, message):

        (_, clients) = self._iam.get_session_and_clients()
        client = clients.get('logs')

        print('CloudWatchLogger: LOG')
        self._ensure_stream_and_token(client)
        ts_ms = int(time.time() * 1000)
        args = {
            "logGroupName": self.log_group,
            "logStreamName": self._current_stream,
            "logEvents": [{"timestamp": ts_ms, "message": message}],
        }
        if self._seq_token:
            args["sequenceToken"] = self._seq_token

        try:
            resp = client.put_log_events(**args)
            print(f'Log sent to cloudwatch: {self.log_group}')
            self._seq_token = resp.get("nextSequenceToken")
        except InvalidSequenceTokenException:
            # Refresh token and retry once
            desc = client.describe_log_streams(
                logGroupName=self.log_group,
                logStreamNamePrefix=self._current_stream,
                limit=1,
            )
            streams = desc.get("logStreams", [])
            self._seq_token = streams[0].get("uploadSequenceToken") if streams else None
            if self._seq_token:
                args["sequenceToken"] = self._seq_token
            else:
                args.pop("sequenceToken", None)

            print(f'Log sent to cloudwatch: {self.log_group}')
            resp = client.put_log_events(**args)
            self._seq_token = resp.get("nextSequenceToken")
        except ClientError as e:
            # You may want to surface/handle throttling, invalid param sizes, etc.
            raise RuntimeError(f"CloudWatch put_log_events failed: {e}") from e


LOG = MsgLogger()
