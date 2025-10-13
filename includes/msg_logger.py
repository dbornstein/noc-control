import logging
import json
import sys
from traceback import extract_stack

from pubnub.utils import extend_list

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


class MsgLocalLogger(MsgLogger):
    def __init__(self, extra_param=None): 
        super().__init__() 
        self.extra_param = extra_param  # Handle the new param

    def send_message(self, msg):
        print(f'[{msg}]')
        print(self.extra_param)
        print('--------------')


LOG = MsgLogger()
