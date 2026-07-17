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

class TailscaleBOF(BaseBOFTask):
    def __init__(self):  
        BaseBOFTask.__init__(self, "tailscale", base_binary_name = "tailscale", base_binary_path=parent_path)
        self.parser.description = "Control a tailscale daemon running on host either via the in-memory tailscaled BOF or the official service."
        
        # Global flags
        self.parser.add_argument('--socket', metavar='PATH',
                        help='path to tailscaled socket')
        
        # Create subparsers
        subparsers = self.parser.add_subparsers(dest='command', help='subcommand help')
        
        # up command
        up_parser = subparsers.add_parser('up', help='Connect to Tailscale')
        #up_parser.add_argument('--accept-dns', action='store_true',
        #                    help='accept DNS configuration from the admin console')
        #up_parser.add_argument('--accept-routes', action='store_true',
        #                    help='accept subnet routes that other nodes advertise')
        #up_parser.add_argument('--accept-risk', metavar='RISK',
        #                    help='accept risk and skip confirmation (lose-ssh, all, or empty)')
        #up_parser.add_argument('--advertise-connector', action='store_true',
        #                    help='offer to be an app connector')
        #up_parser.add_argument('--advertise-exit-node', action='store_true',
        #                    help='offer to be an exit node')
        #up_parser.add_argument('--advertise-routes', metavar='IP',
        #                    help='expose physical subnet routes')
        #up_parser.add_argument('--advertise-tags', metavar='TAGS',
        #                    help='give tagged permissions to this device')
        up_parser.add_argument('--auth-key', metavar='KEY',
                            help='provide an auth key to automatically authenticate')
        #up_parser.add_argument('--exit-node', metavar='IP|NAME',
        #                    help='Tailscale IP or machine name to use as exit node')
        #up_parser.add_argument('--exit-node-allow-lan-access', action='store_true',
        #                    help='allow LAN access while connected to exit node')
        #up_parser.add_argument('--force-reauth', action='store_true',
        #                    help='force re-authentication')
        #up_parser.add_argument('--hostname', metavar='NAME',
        #                    help='hostname to use instead of OS-provided')
        #up_parser.add_argument('--json', action='store_true',
        #                    help='output in JSON format')
        up_parser.add_argument('--login-server', metavar='URL',
                            help='base URL of control server')
        #up_parser.add_argument('--netfilter-mode', metavar='MODE',
        #                    choices=['on', 'nodivert', 'off'],
        #                    help='netfilter mode (on, nodivert, off)')
        #up_parser.add_argument('--nickname', metavar='NAME',
        #                    help='nickname for the current account')
        #up_parser.add_argument('--operator', metavar='USER',
        #                    help='Unix username to operate tailscaled')
        #up_parser.add_argument('--qr', action='store_true',
        #                    help='generate QR code for login URL')
        #up_parser.add_argument('--reset', action='store_true',
        #                    help='reset unspecified settings to default')
        #up_parser.add_argument('--shields-up', action='store_true',
        #                    help='block incoming connections')
        #up_parser.add_argument('--snat-subnet-routes', action='store_true',
        #                    help='source NAT traffic to local routes')
        #up_parser.add_argument('--ssh', action='store_true',
        #                    help='run Tailscale SSH server')
        #up_parser.add_argument('--stateful-filtering', action='store_true',
        #                    help='enable stateful filtering')
        #up_parser.add_argument('--timeout', metavar='DURATION',
        #                    help='maximum time to wait for service initialization')
        #up_parser.add_argument('--unattended', action='store_true',
        #                    help='(Windows only) run in unattended mode')
        
        # down command
        down_parser = subparsers.add_parser('down', help='Disconnect from Tailscale')
        #down_parser.add_argument('--accept-risk', metavar='RISK',
        #                        help='accept risk and skip confirmation')
        #down_parser.add_argument('--reason', metavar='DESCRIPTION',
        #                        help='reason for disconnecting')        
 
        # ip command
        #ip_parser = subparsers.add_parser('ip', help='Get Tailscale IP address')
        #ip_parser.add_argument('hostname', nargs='?', help='hostname to query')
        #ip_parser.add_argument('-4', '--ipv4', action='store_true', dest='ipv4',
        #                    help='only return IPv4 address')
        #ip_parser.add_argument('-6', '--ipv6', action='store_true', dest='ipv6',
        #                    help='only return IPv6 address')
        #ip_parser.add_argument('-1', action='store_true', dest='one',
        #                    help='only return one address, preferring IPv4')
                              
        # set command
        set_parser = subparsers.add_parser('set', help='Change preferences')
        #set_parser.add_argument('--accept-dns', metavar='BOOL',
        #                    help='accept DNS configuration')
        #set_parser.add_argument('--accept-risk', metavar='RISK',
        #                    help='accept risk')
        #set_parser.add_argument('--accept-routes', metavar='BOOL',
        #                    help='accept subnet routes')
        #set_parser.add_argument('--advertise-connector', metavar='BOOL',
        #                    help='offer to be app connector')
        #set_parser.add_argument('--advertise-exit-node', metavar='BOOL',
        #                    help='offer to be exit node')
        set_parser.add_argument('--advertise-routes', metavar='IP',
                            help='expose subnet routes')
        #set_parser.add_argument('--auto-update', metavar='BOOL',
        #                    help='enable/disable auto-updates')
        #set_parser.add_argument('--exit-node', metavar='IP|NAME',
        #                    help='exit node to use')
        #set_parser.add_argument('--exit-node-allow-lan-access', metavar='BOOL',
        #                    help='allow LAN access with exit node')
        #set_parser.add_argument('--hostname', metavar='NAME',
        #                    help='hostname to use')
        #set_parser.add_argument('--netfilter-mode', metavar='MODE',
        #                    choices=['on', 'nodivert', 'off'],
        #                    help='netfilter mode')
        #set_parser.add_argument('--nickname', metavar='NAME',
        #                    help='nickname for account')
        #set_parser.add_argument('--operator', metavar='USER',
        #                    help='Unix username to operate tailscaled')
        #set_parser.add_argument('--report-posture', metavar='BOOL',
        #                    help='allow device posture gathering')
        #set_parser.add_argument('--shields-up', metavar='BOOL',
        #                    help='block incoming connections')
        #set_parser.add_argument('--snat-subnet-routes', metavar='BOOL',
        #                    help='source NAT subnet routes')
        #set_parser.add_argument('--ssh', metavar='BOOL',
        #                    help='run SSH server')
        #set_parser.add_argument('--stateful-filtering', metavar='BOOL',
        #                    help='enable stateful filtering')
        #set_parser.add_argument('--update-check', metavar='BOOL',
        #                    help='notify about updates')
        #set_parser.add_argument('--webclient', metavar='BOOL',
        #                    help='expose web interface')
                
        # status command
        status_parser = subparsers.add_parser('status',
                                            help='Get connection status')
        #status_parser.add_argument('--active', action='store_true',
        #                        help='filter to active peers only')
        #status_parser.add_argument('--browser', metavar='BOOL', default='true',
        #                        help='open browser in web mode')
        status_parser.add_argument('--json', action='store_true',
                                help='output in JSON format')
        #status_parser.add_argument('--listen', metavar='ADDRESS',
        #                        default='127.0.0.1:8384',
        #                        help='listen address for web mode')
        #status_parser.add_argument('--peers', metavar='BOOL', default='true',
        #                        help='show peer status')
        #status_parser.add_argument('--self', metavar='BOOL', default='true',
        #                        help='show local machine status')
        #status_parser.add_argument('--web', action='store_true',
        #                        help='run webserver with status')

    # netcheck - Print an analysis of local network conditions
        netcheck_parser = subparsers.add_parser('netcheck', help='Print an analysis of local network conditions')
        netcheck_parser.add_argument('--endpoint', help='Different to the official client, test for network connectivity against a specific DERP server')        
        #netcheck_parser.add_argument('--every', metavar='DURATION',
        #                            help='if non-zero, do an incremental report with the given frequency')
        #netcheck_parser.add_argument('--format', choices=['', 'json'], default='',
        #                            help='output format (empty for human-readable, "json" for JSON)')
        #netcheck_parser.add_argument('--verbose', '-v', action='store_true',
        #                        help='verbose logs')        
        
        shutdown_parser = subparsers.add_parser('shutdown', help='Shutdown the running tailscaled instance')
         

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:

        if not arguments:
            raise TaskInvalidArgumentsException("No args provided")

        #Just parse the arguments to make sure they are valid
        parser_arguments = self.parser.parse_args(arguments)
        
        #Now just pack all the args as provided to the BOF itself 
        result = []
        for arg in arguments:
            result.append((BOFArgumentEncoding.STR, arg))

        return result                
    