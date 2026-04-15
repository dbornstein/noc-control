#!/usr/bin/env python3

import optparse
import os
import sys

# Add includes/ to path for msg_logger, iam_role_anywhere, exceptions
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'includes'))

from agent.config import load_config
from agent.loop   import run
from msg_logger   import MsgLocalLogger


def main(argv):
    with open(os.path.join(os.path.dirname(__file__), 'agent_version'), 'r') as fh:
        version = fh.read().strip()
    print(f'Starting noc-agent version: {version}')

    parser = optparse.OptionParser(usage='usage: prog [options]')
    group  = optparse.OptionGroup(parser, 'Agent options')
    group.add_option('--id',          dest='agent_id',    default=None,
                     help='Agent ID (overrides config file)')
    group.add_option('--cfg',         dest='config_id',   default=None,
                     help='Config ID (overrides config file)')
    group.add_option('--config-file', dest='config_file', default='agent_config.json',
                     help='Path to local agent config JSON (default: agent_config.json)')
    group.add_option('--agent',       dest='run_agent',   action='store_true', default=True,
                     help='Run the PubNub agent loop (default)')
    parser.add_option_group(group)
    options, _ = parser.parse_args(argv[1:])

    cfg = load_config(
        {},
        agent_id       = options.agent_id,
        config_id      = options.config_id,
        agent_cfg_file = options.config_file,
    )

    log = MsgLocalLogger(cfg)

    run(cfg, log, version)


if __name__ == '__main__':
    main(sys.argv)
