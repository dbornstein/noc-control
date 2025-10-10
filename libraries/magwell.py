
import urllib3
import hashlib
import json


def magwell_login(cfg, device):

    device_ip = device.get('ipAddress')
    device_id = device.get('deviceId')
    username = device.get('username')
    password = device.get('password')

    device_url = f'http://{device_ip}/mwapi'

    md5_password = hashlib.md5(password.encode('utf-8')).hexdigest()

    params = {
        "method": "login",
        "id": f'{username}',
        "pass": md5_password
    }
    print(f'\tLogging into: {device_url}')
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

            print(f'\tsetting sid: {sid} on {device_id}')
            device['status'] = 'online'
            device['sid'] = sid
            cfg['localDevices'][device_id] = device
            return True
        else:
            print(f'\t**Error: Login Status code: {response.status}')

    except Exception as e:
        print(f'[{device_id}]: connect failed - {e}')

    print('\tSetting device to offline')
    device['status'] = 'offline'
    return False




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
            res = json.loads(response.data.decode('utf-8'))
            status = res.get('status')
            if status == 0:
                # We are good.
                break
            elif status == 37:
                print('Login expired(37): calling login')
                magwell_login(cfg,device)
                count += 1
                continue
            else:
                print(f'Status not ok: {res}')
                count +=1 
        else:
            r = response.data.decode('utf-8')
            print(f'bad response[{response.status}]: {r}')
            http.clear()
            return False
    print(f'response: {response.data.decode('utf-8')}')
    return True
    
      