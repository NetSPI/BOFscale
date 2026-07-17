import sys
import os


from typing import List, Tuple, Optional, Dict
from pathlib import Path
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFType, BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException

def _resolve_binary_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(script_dir).lower() == "ost":
        return os.path.normpath(os.path.join(script_dir, "../pe"))
    return script_dir

script_path = _resolve_binary_path()
parent_path = script_path
class TailscaledBOF(BaseBOFTask):
    def __init__(self):  
        BaseBOFTask.__init__(self, "tailscaled", base_binary_name = "tailscaled", base_binary_path=parent_path, bof_type=BOFType.ASYNC )
        self.parser.description = "Run a tailscaled daemon in-process asynchronously. Defaults to userspace networking and in memory node state"

        self.parser.add_argument('--state', default='mem:', help='path to state file or directory')
        self.parser.add_argument('--socket', default='', help='path to listening socket (default: random GUID)')
        self.parser.add_argument('--port', type=int, default=0, help='UDP port to listen on for WireGuard and peer-to-peer traffic (0 means auto-select)')
        self.parser.add_argument('--socks5-server', default='', help='address to run SOCKS5 proxy on, e.g., localhost:1080')
        self.parser.add_argument('--outbound-http-proxy-listen', default='', help='address to run outbound HTTP proxy on, e.g., localhost:8080')
        self.parser.add_argument('--tun', default='userspace-networking', help='tunnel interface name')
        self.parser.add_argument('--debug', default='', help='address to run debug server on, e.g., localhost:8080')
        self.parser.add_argument('--verbose', '-v', action='count', default=0, help='increase logging verbosity (can be specified multiple times)')
        self.parser.add_argument('--cleanup', action='store_true', help='clean up system state and exit')
        self.parser.add_argument('--statedir', default='', help='legacy flag, use --state instead')
        self.parser.add_argument('--no-logs-no-support', action='store_true', help='disable log uploads; note: without logs, support is limited (default)')
        self.parser.add_argument('--disable-log-timestamps', action='store_true', help='disable timestamps in log output')
     
    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
  
        result = []

        for arg in arguments:
            result.append((BOFArgumentEncoding.STR, arg))

        return result                
    