#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import json

import logging

import urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlencode

import requests
import subprocess
import json
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlencode
import time
import os

import hashlib
import optparse
import traceback
from urllib.parse import parse_qs, quote
from urllib.parse import urlencode

from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub, SubscribeListener

# commonPath = "{0}/common".format(os.path.dirname(os.path.abspath(__file__)))
# sys.path.append( commonPath)

# Configure PubNub
pnconfig = PNConfiguration()
cfg = {}

def main(argv):
    global cfg

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



    parser.add_option_group(admin)
    (options, args) = parser.parse_args()

    cfg = load_config(cfg, options.config_file)

    executeCommands(cfg, options)
    sys.exit()



def executeCommands(cfg, options):
    if options.agent:
        agent_listen(cfg)
        sys.exit()

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
        print(f'Message Received:{message}')

        command =  message.get('command')
        if command not in ['refresh', 'stop', 'play', 'status','update']:
            print(f'Error: Invalid Command:{command}')
            return

        ''' Appliance Based commands '''
        if command in ['refresh', 'update']:
            agent_id = message.get('agentId')
            local_agent_id = cfg.get('agentId')
            if agent_id != local_agent_id:
                print(f'{command} for {agent_id} not for this agent ({local_agent_id})')
                return
            if command == 'refresh':
                print('refresh command received')
                cfg = load_config(cfg)
                setup_devices_for_location(cfg)
                print('refresh complete')
                return
            if command == 'update':
                execute_agent_update()
                return


        device_id = message.get('deviceId')
        local_devices = cfg.get('localDevices')
        device = local_devices.get(device_id)
        device_type = device.get('deviceType')

        if not device:
            print(f'device [{device_id}] not registered in this location')
            return

        if command == 'stop':
            stream_name = device.get('streamName')
            print('stopping stream: {stream_name}')
            if device_type == 'magwell':

                params = {
                    "method": "clear-channels",
                    "name": stream_name
                }
                send_magwell_command(cfg, device_id, params)
                return

        elif command == 'status':
            if device_type == 'magwell':

                params = {
                    "method": "get-signal-info",
                }
                res = send_magwell_command(cfg, device_id, params)
                print(res)
                return

        elif command == 'play':
            stream_url = message.get('streamUrl')
            stream_name = message.get('streamName')

            device['streamName'] = stream_name
            device['streamUrl'] = stream_url


            print(f'Device Type: {device_type}')

            if device_type == 'magwell':

                #http://d15w0nire27phg.cloudfront.net/NBCU-LATAM/enc_index.m3u8?mw-bitrate=4096&mw-buffer-duration=60
                #http://d15w0nire27phg.cloudfront.net/NBCU-LATAM/enc_index.m3u8?mw-bitrate=4096&mw-buffer-duration=60
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
    except Exception as e:
        print(f'process_message exception: {e}')
        trace = traceback.format_exc()
        print(trace)


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


def magwell_login(cfg, device):

    device_ip = device.get('ipAddress')
    device_id = device.get('deviceId')
    username = device.get('username')
    password = device.get('password')

    device_url = f'http://{device_ip}/mwapi'

    md5_password = hashlib.md5(password.encode('utf-8')).hexdigest()
    print(f'md5-password: {md5_password}')

    params = {
        "method": "login",
        "id": f'{username}',
        "pass": md5_password
    }
    print(f'Logging into: {device_url}')
    try:
        http = urllib3.PoolManager(timeout=urllib3.Timeout(connect=10.0, read=10.0))
       
        response = http.request("GET", device_url, fields=params, timeout=urllib3.Timeout(connect=5, read=15))
        http.clear()
      
        sid = None
        if response.status == 200:
            sid = None
            for header, value in response.headers.items():
                if header.lower() == 'set-cookie':
                    sid = value.split(';')[0].split('=')[1]

            print(f'setting sid: {sid} on {device_id}')
            device['status'] = 'online'
            device['sid'] = sid
            cfg['localDevices'][device_id] = device
            return True
        else:
            print(f'Error: Login Status code: {response.status}')

    except Exception as e:
        print(f'[{device_id}]: connect failed - {e}')

    device['status'] = 'offline'
    return False


# Usage post-PubNub receipt (e.g., {"action": "switch", "tvc": "NJMCR_M1", "ndi_url": "ndi://tag-stream-from-mongo"}):
# response = magwell_http('http://10.11.4.11/mwapi', {'method': 'login', ...}, tvc_id='NJMCR_M1')
# if response.status_code == 200 and response.json().get('status') == 0:
#     sid = response.cookies.get('sid')
#     # Mongo update: db.tvc_sessions.update_one({'ip': '10.11.4.11'}, {'$set': {'sid': sid}})
#     # Follow-up: set-channel with NDI URL via session


def send_magwell_command(cfg, device_id, params):

    print('--------- Sending Magwell Command+++++++++')
    print(params)
    print(f'sending command to: {device_id}')
    device = cfg.get('localDevices',{}).get(device_id)
    sid = device.get('sid')
    ip = device.get('ipAddress')
    url = f'http://{ip}/mwapi'


    headers = {
        'Cookie': f'sid={sid}'
    }
    print(f'\t [url]:     {url}')
    print(f'\t [headers]: {headers}')
    print(f'\t [params]:  {params}')

    http = urllib3.PoolManager(timeout=urllib3.Timeout(connect=6.0, read=6.0))
    # Try 3 times
    count = 0
    response = ''
    while count < 3:
        response = http.request("GET", url, fields=params, headers=headers)
        if response.status == 200:
            print('200: ok')
            break
        if response.status == 37:
            print('37: calling login')
            magwell_login(cfg,device)
            count += 1
            continue
        count += 1
        print(response.data.decode('utf-8'))
        print('++++++++++++++++++++++++++++++++++++++\n')
    http.clear()
    print(f'response: {response.data.decode('utf-8')}')

    #return json.loads(response.data.decode('utf-8'))
    
        

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


def send_vlc_command(cfg, stream_url):

    vlc_hostname = cfg.get('vlcHostname')
    vlc_port = cfg.get('vlcPort')
    vlc_password = cfg.get('vlcPassword')

    http = urllib3.PoolManager()
    headers = urllib3.util.make_headers(basic_auth=f':{vlc_password}')

    url = f'http://{vlc_hostname}:{vlc_port}/requests/status.xml?command=in_play&input={stream_url}'
    response = http.request("GET", url, headers=headers)
    if response.status != 200:
        print(f"Failed to send command, status: {response.status}")
        print(response.data.decode('utf-8'))

    play_url = f'http://{vlc_hostname}:{vlc_port}/requests/status.xml?command=pl_play'
    response = http.request("GET", play_url, headers=headers)
    if response.status != 200:
        print(f"Failed to send command, status: {response.status}")
        print(response.data.decode('utf-8'))


def start_vlc_subprocess(cfg):
    # Launch VLC in a subprocess with HTTP interface

    if not cfg.get('vlcAutostart'):
        return

    if cfg.get('VLC_RUNNING'):
        return

    cfg['VLC_RUNNING'] = True

    print('starting VLC process')
    vlc_hostname = cfg.get('vlcHostname')
    vlc_port = cfg.get('vlcPort')
    vlc_password = cfg.get('vlcPassword')
    vlc_delay = cfg.get('vlcStartDelay')
    vlc_command = cfg.get('vlcCommand', 'vlc')


    vlc_cmd = [
        vlc_command,
        '--extraintf', 'http',
        '--http-port', f'{vlc_port}',
        '--http-password', f'{vlc_password}',
        '--no-playlist-autostart',
        '--no-video-title-show'
    ]
    print(f'vlc Command: {vlc_cmd}')

    # Use subprocess.Popen to fork and exec
    process = subprocess.Popen(vlc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(vlc_delay)
    return process


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


if __name__ == '__main__':
	main(sys.argv)
	sys.exit()
