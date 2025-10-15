#!/usr/bin/env python3

import os
import sys

import subprocess
import time
import json
import time
import os
import optparse
import traceback
import urllib3
from urllib3.util.retry import Retry
from urllib.parse import parse_qs, quote, urlencode
from datetime import datetime

from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub, SubscribeListener

# add includes to the path to access the local include directory
commonPath = "{0}/includes".format(os.path.dirname(os.path.abspath(__file__)))
sys.path.append( commonPath)

from magwell import send_magwell_command, magwell_login
from vlc import send_vlc_command, start_vlc_subprocess
from exceptions import *

# Configure PubNub
pnconfig = PNConfiguration()
cfg = {}

# setup Logger, then override it with Local Logger.
from msg_logger import MsgLocalLogger
from msg_logger import LOG
details = {'a': 'b'}



def main(argv):
    global cfg
    global LOG

    with open("agent_version", "r") as f:
        version = f.read().strip()
    print(f'starting agent version: {version}')

    usage = "usage: prog command [options]\n\n"
    parser = optparse.OptionParser(usage=usage, version="%prog 1.2")

    admin = optparse.OptionGroup(parser, "Local Agent Commands","Local Commands")

    admin.add_option("--agent", action="store_true", dest="agent",default=False,
    				 help="Run as event agent")

    admin.add_option("--config-file", action="store", dest="config_file",default='agent_config.json',
    				 help="agent config-file (def=agent_config.cfg)")

    admin.add_option("--byte-encode-file", action="store", dest="byte_encode",default='',
    				 help="byte encode secret file")


    parser.add_option_group(admin)
    (options, args) = parser.parse_args()

    cfg = load_config(cfg, options.config_file)

    LOG = MsgLocalLogger(cfg)

    executeCommands(cfg, options)
    sys.exit()



def executeCommands(cfg, options):

    if options.byte_encode:
        byte_encode(cfg, options.byte_encode)

    if options.agent:
        agent_listen(cfg)
        sys.exit()



'''
Starts the Agent Listener thread. On each pubnub message received, this thread calls
process message
'''
def agent_listen(cfg):

    agent_id = cfg.get('agentConfig').get('agentId')

    pn_cfg = cfg.get('pubnubConfig')
    pnconfig.subscribe_key = pn_cfg .get('subscribeKey')
    pnconfig.publish_key = pn_cfg .get('publishKey')
    pnconfig.user_id = agent_id
    pnconfig.enable_subscribe = True
    pubnub = PubNub(pnconfig)

    setup_devices_for_location(cfg)

    status_listener = StatusListener()
    pubnub.add_listener(status_listener)

    stack = cfg.get('stack')
    # Subscribe to the channel
    channel = f'{stack}-pnchannel'
    subscription = pubnub.channel(channel).subscription()
    subscription.on_message = lambda message: process_message(cfg, message.message)
    subscription.subscribe()
    print(f'Subscribed to channel: {channel}')

    # Keep the program running to listen (use Ctrl+C to stop)
    while True:
        time.sleep(1)


def process_message(cfg, message):

    try:
        LOG.reset()
        LOG.set('success',True)
        LOG.set('log_type', 'control_message')
        LOG.set('message', message)
        print(f'Message Received:{message}')

        command =  message.get('command')
        if command not in ['refresh', 'stop', 'play', 'status','update']:
            raise InvalidDataError(f'Error: Invalid Command:{command}')

        ''' Appliance Based commands '''
        if command in ['refresh', 'update']:
            agent_id = message.get('agentId')
            local_agent_id = cfg.get('agentId')
            if agent_id != local_agent_id:
                print(f'{command} for {agent_id} not for this agent ({local_agent_id})')
                raise IgnoreMessageException('NotForThisAgent')
    
            if command == 'refresh':
                print('refresh command received')
                cfg = load_config(cfg)
                setup_devices_for_location(cfg)
                LOG.set('command_status', 'refresh complete')
                print('refresh complete')
                return

            if command == 'update':
                LOG.set('command_status', 'update initiated')
                execute_agent_update()
                return

        device_id = message.get('deviceId')
        local_devices = cfg.get('localDevices')
        device = local_devices.get(device_id)
        if not device:
            print(f'device [{device_id}] not registered in this location')
            raise IgnoreMessageException('NotForThisAgent')

        device_type = device.get('deviceType')
        LOG.set('device_id', device_id)
        LOG.set('device_type', device_type)
        LOG.set('device', device)
        LOG.set('local_devices', local_devices)

        if command == 'stop':
            stream_name = device.get('streamName')
            print(f'stopping stream: {stream_name}')
            if device_type == 'magwell':

                params = {
                    "method": "clear-channels",
                    "name": stream_name
                }
                res = send_magwell_command(cfg, device_id, params)
                return

        elif command == 'status':
            if device_type == 'magwell':

                params = {
                    "method": "get-signal-info",
                }
                res = send_magwell_command(cfg, device_id, params)
                LOG.set('magwell_response',res)
                print(res)
                return

        elif command == 'play':
            stream_url = message.get('streamUrl')
            stream_name = message.get('streamName')

            device['streamName'] = stream_name
            device['streamUrl'] = stream_url


            print(f'Device Type: {device_type}')

            if device_type == 'magwell':

                params = {
                    "method": "add-channel",
                    "name": stream_name,
                    "url": stream_url,
                    "hotkey": "none",
                    "mw-bitrate": 4096,
                    "mw-buffer-duration": 60
                }
                send_magwell_command(cfg, device_id, params)

                params = {
                    "method": "set-channel",
                    "name": stream_name,
                    "ndi-name": "false"
                }
                send_magwell_command(cfg, device_id, params)


                #http://192.168.1.100/mwapi?method=add-channel&name=DAVE2&url=http:%2F%2Fd15w0nire27phg.cloudfront.net%2FNBCU-LATAM%2Fenc_index.m3u8%3Fmw-bitrate%3D4096%26mw-buffer-duration%3D60&hotkey=none
                #http://192.168.1.100/mwapi?method=set-channel&ndi-name=false&name=DAVE
            elif device_type == 'vlc':

                if not cfg.get('vlcEnabled'):
                    print('VLC not enabled in agent config.')
                    return

                vlc_hostname = cfg.get('vlcHostname')
                if vlc_hostname in ['localhost', '127.0.0.1']:
                    start_vlc_subprocess(cfg)

                send_vlc_command(cfg, stream_url)
            #update_device_status(cfg)
    except IgnoreMessageException as e:
        print('message not for this agent.')
        # Don't send a log.
        LOG.reset()
        return
    except Exception as e:
        print(f'process_message exception: {e}')
        trace = traceback.format_exc()
        LOG.set('EXCEPTION', str(e))
        LOG.set('EXCEPTION_TRACE', trace)
        print(trace)
    finally:
        print('sending log message')
        LOG.send()


def setup_devices_for_location(cfg):

    local_devices = cfg.get('localDevices')

    for device_id in local_devices:
        device = local_devices.get(device_id)
        device_name = device.get('deviceName')
        device_type = device.get('deviceType')

        print(f'processing device: {device_name}')

        if device_type == 'magwell':
            res = magwell_login(cfg, device)
        else:
            device['status']  = 'online'

    #update_device_status(cfg)


# Usage post-PubNub receipt (e.g., {"action": "switch", "tvc": "NJMCR_M1", "ndi_url": "ndi://tag-stream-from-mongo"}):
# response = magwell_http('http://10.11.4.11/mwapi', {'method': 'login', ...}, tvc_id='NJMCR_M1')
# if response.status_code == 200 and response.json().get('status') == 0:
#     sid = response.cookies.get('sid')
#     # Mongo update: db.tvc_sessions.update_one({'ip': '10.11.4.11'}, {'$set': {'sid': sid}})
#     # Follow-up: set-channel with NDI URL via session

  

def update_device_status(cfg):
    print('sending updated status')
    vals = {}
    vals['configId'] = cfg.get('configId')
    vals['operation'] = 'update_device_status'
    url = cfg.get('controlEndpoint').format(**vals)
    body = json.dumps(cfg.get('localdevices'))

    apikey = cfg.get('apiKey')
    headers = { 'x-api-key': apikey}

    # Send a POST request
    http = urllib3.PoolManager(timeout=urllib3.Timeout(connect=10.0, read=10.0))
    response = http.request(
    	'POST',
    	url,
    	body=body,
    	headers=headers
    )

    if response.status != 200:
        raise Exception(f'Error posting device status: {response.status}')
    http.clear()


def load_config(cfg, agent_cfg_file=None):

    local_cfg = cfg.get('localConfig',{})
    if not local_cfg:
        # Open and load the JSON data
        with open(agent_cfg_file, 'r') as file:
            local_cfg = json.load(file)

        if cfg.get('agentId') == 'noc-agent-xxx':
            print(f'ERROR: agentId must be set in {agent_cfg_file}')
            sys.exit()

    api_endpoint = local_cfg.get('apiEndpoint')
    config_id = local_cfg.get('configId')
    apikey = local_cfg.get('apiKey')
    agent_id = local_cfg.get('agentId')
    print(f'Local Agent ID: {agent_id}')


    headers = { 'x-api-key': apikey}

    cfg_url = f'{api_endpoint}/admin/{config_id}/config'
    print(cfg_url)
    cfg = download_json(cfg_url, headers)
    cfg['localConfig'] = local_cfg

    # Download the full agent config.
    agent_url = f'{api_endpoint}/query/{config_id}/agents/{agent_id}'
    print(agent_url)

    res = download_json(agent_url, headers, db_api=True)
    if not res:
        print(f'failed to download agentId: {agent_id}')
        sys.exit()


    agent_cfg = res[0]
    cfg['agentConfig'] = agent_cfg
    cfg = cfg | agent_cfg

    # Download the devices for this agent
    locations = agent_cfg.get('serveLocations','')
    val = ','.join(str(loc) for loc in locations)
    qs = f'?location={val}'
    devices_url = f'{api_endpoint}/query/{config_id}/devices{qs}'
    print(devices_url)
    device_list = download_json(devices_url, headers,db_api=True)
    if not device_list:
        print(f'no devices for location: {val}')
        sys.exit()

    local_devices = {}
    for device in device_list:
        if not device.get('enabled',False):
            continue
        device_id = device.get('deviceId')
        local_devices[device_id] = device

    cfg['localDevices'] = local_devices

    return cfg



def download_json(url, headers=None, db_api=False):
    http = urllib3.PoolManager()
    try:
        response = http.request("GET", url, headers=headers)
        if response.status == 200:
            res = json.loads(response.data.decode("utf-8"))
            if not db_api:
                return res
            return res.get('entries')

            # xxx put pagination code in here.
        else:
            raise Exception(f"Failed to download JSON. Status code: {response.status}")
    finally:
        http.clear()  # Optional: clean up the connection pool


# Status listener for connection feedback
class StatusListener(SubscribeListener):
    def status(self, pubnub, status):
        print(f'Status: {status.category.name}')


def execute_agent_update():

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    script_path = '/opt/noc-agent/update.sh'
    try:
        # Run silently; capture for local log (non-blocking)
        result = subprocess.run(
            [script_path, '--silent'],
            check=True,
            capture_output=True,
            text=True,
            cwd='/opt/noc-agent'
        )
        logger.info(f"Update stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.warning(f"Update stderr: {result.stderr.strip()}")

        logger.info("Update initiated; restarting via systemd...")

    except subprocess.CalledProcessError as e:
        error_msg = f"Update failed (code {e.returncode}): {e.stderr}"
        logger.error(error_msg)
        # No PubNub publish; rely on HA peer or manual check
    except FileNotFoundError:
        logger.error(f"update.sh not found at {script_path}")


def byte_encode(cfg, filename):

    
    with open(filename, "r", encoding="utf-8") as f:
        contents = f.read()

    bytes = contents.encode('utf-8')
    print
    print(bytes)
    print



if __name__ == '__main__':
	main(sys.argv)
	sys.exit()


# # create_client_creds.py
# # pip install boto3
# import os, json, secrets, string, boto3
# 
# REGION = os.getenv("AWS_REGION", "us-east-1")
# SECRET_ID = os.getenv("OAUTH_SECRET_ID", "thirdparty/oauth/client")
# 
# def rand_secret(n=48):
#     alphabet = string.ascii_letters + string.digits + "-_"
#     return "".join(secrets.choice(alphabet) for _ in range(n))
# 
# def main():
#     client_id = secrets.token_urlsafe(24)   # e.g. CcX... (URL-safe)
#     client_secret = rand_secret(64)         # strong shared secret
# 
#     sm = boto3.client("secretsmanager", region_name=REGION)
#     payload = json.dumps({"client_id": client_id, "client_secret": client_secret})
#     try:
#         sm.create_secret(Name=SECRET_ID, SecretString=payload)
#     except sm.exceptions.ResourceExistsException:
#         sm.put_secret_value(SecretId=SECRET_ID, SecretString=payload)
# 
#     print("Created/updated secret:", SECRET_ID)
#     print("client_id:", client_id)
#     print("client_secret (DO NOT EMAIL/LOG IN CLEAR):", client_secret[:4] + "…")
# 
# if __name__ == "__main__":
#     main()

# ============================================================================
# ============================================================================
# ============================================================================
# pip install iam-rolesanywhere-session boto3
# import os
# from iam_rolesanywhere_session import IAMRolesAnywhereSession
# 
# TRUST_ANCHOR_ARN = os.getenv("RA_TRUST_ANCHOR_ARN")
# PROFILE_ARN      = os.getenv("RA_PROFILE_ARN")
# ROLE_ARN         = os.getenv("RA_ROLE_ARN")
# REGION           = os.getenv("AWS_REGION", "us-east-1")
# 
# CERT_PATH        = os.getenv("RA_CERT_PATH", "./client.pem")       # leaf cert
# KEY_PATH         = os.getenv("RA_KEY_PATH", "./client.key")        # matching private key
# CHAIN_PATH       = os.getenv("RA_CHAIN_PATH")                      # optional: intermediates bundle (no leaf, no root)
# DURATION_SECONDS = int(os.getenv("RA_DURATION", "3600"))           # 900..43200, subject to profile/role limits
# SESSION_NAME     = os.getenv("RA_SESSION_NAME", "roleanywhere-python")

# kwargs = dict(
#     profile_arn=PROFILE_ARN,
#     role_arn=ROLE_ARN,
#     trust_anchor_arn=TRUST_ANCHOR_ARN,
#     certificate=CERT_PATH,
#     private_key=KEY_PATH,
#     region=REGION,
#     session_duration=DURATION_SECONDS,
# )
# 
# # If you have intermediates, include them:
# if CHAIN_PATH:
#     kwargs["certificate_chain"] = CHAIN_PATH  # param supported by the library
# 
# # Build a refreshable boto3 Session backed by Roles Anywhere:
# session = IAMRolesAnywhereSession(**kwargs).get_session()
# 
# # # Example: verify identity and list S3 buckets
# # sts = session.client("sts")
# # print(sts.get_caller_identity())
# # 
# # s3 = session.client("s3")
# # print([b["Name"] for b in s3.list_buckets().get("Buckets", [])])
# 
# ==============================================
# ==============================================
# ==============================================
# 
# import boto3
# 
# logs = boto3.client('logs', region_name='us-east-1')
# 
# log_group = '/my/app/logs'
# log_stream = 'python-function-stream'
# 
# # Ensure log group exists
# try:
#     logs.create_log_group(logGroupName=log_group)
# except logs.exceptions.ResourceAlreadyExistsException:
#     pass
# 
# # Ensure log stream exists
# try:
#     logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
# except logs.exceptions.ResourceAlreadyExistsException:
#     pass
# 
# ==============================================
# ==============================================
# ==============================================
# import time
# 
# # Get the current timestamp in milliseconds
# timestamp = int(round(time.time() * 1000))
# 
# # Retrieve the next sequence token
# response = logs.describe_log_streams(
#     logGroupName=log_group,
#     logStreamNamePrefix=log_stream
# )
# sequence_token = response['logStreams'][0].get('uploadSequenceToken')
# 
# # Send the log
# log_event = {
#     'logGroupName': log_group,
#     'logStreamName': log_stream,
#     'logEvents': [
#         {'timestamp': timestamp, 'message': 'Hello from boto3!'}
#     ]
# }
# 
# if sequence_token:
#     log_event['sequenceToken'] = sequence_token
# 
# logs.put_log_events(**log_event)
