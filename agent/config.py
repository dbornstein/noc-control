import json
import sys
import urllib3


def download_json(url: str, headers: dict = None) -> dict:
    """GET a URL and return the parsed JSON body."""
    http = urllib3.PoolManager()
    try:
        response = http.request('GET', url, headers=headers or {})
        if response.status == 200:
            return json.loads(response.data.decode('utf-8'))
        raise Exception(f'Failed to download JSON: {url} [{response.status}]')
    finally:
        http.clear()


def load_config(cfg: dict, agent_id: str = None, config_id: str = None,
                agent_cfg_file: str = None) -> dict:
    """
    Load (or reload) the agent configuration.

    On first call pass agent_cfg_file; the local bootstrap JSON is read from
    disk and merged with remote config downloaded from the control Lambda.
    On subsequent calls (e.g. after a 'refresh' command) the localConfig is
    preserved from the existing cfg dict.
    """
    local_cfg = cfg.get('localConfig', {})

    if not local_cfg:
        print(f'Reading local config: {agent_cfg_file}')
        try:
            with open(agent_cfg_file, 'r') as fh:
                local_cfg = json.load(fh)
        except FileNotFoundError:
            print(f'{agent_cfg_file} not found.  Copy from agent_config_template.json and set agentId')
            sys.exit(1)

        # CLI overrides take priority over file values
        local_cfg['agentId']  = agent_id  or local_cfg.get('agentId')
        local_cfg['configId'] = config_id or local_cfg.get('configId')

    if not local_cfg.get('agentId'):
        print(f'ERROR: agentId must be set in [{agent_cfg_file}]')
        sys.exit(1)

    api_endpoint = local_cfg.get('apiEndpoint')
    config_id    = local_cfg.get('configId')
    agent_id     = local_cfg.get('agentId')
    apikey       = local_cfg.get('apiKey')

    print('-----------------------------------------')
    print(f'Agent ID: {agent_id}')
    print(f'ConfigID: {config_id}')
    print('-----------------------------------------')

    cfg_url = f'{api_endpoint}/control/{config_id}/config/agent/{agent_id}'
    print(cfg_url)

    remote = download_json(cfg_url, headers={'x-api-key': apikey})

    # Merge: remote top-level → then agentConfig sub-section → preserve localConfig
    new_cfg = {**remote, **remote.get('agentConfig', {})}
    new_cfg['localConfig']  = local_cfg
    new_cfg['localDevices'] = {}

    return new_cfg
