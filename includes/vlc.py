
import urllib3
import subprocess
import time


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
    retcode = process.poll() 
    if not retcode:
        print('process is running')
    else:
        print(f'VLC process exited with status: {retcode}')
    return process

