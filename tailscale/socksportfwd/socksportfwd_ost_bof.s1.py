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
        BaseBOFTask.__init__(self, "socksportfwd", base_binary_name = "socksportfwd", base_binary_path=parent_path, bof_type=BOFType.ASYNC)
        self.parser.description = "Leverage a SOCK5 proxy to port forward a specific TCP port."
        
        self.parser.add_argument('--l', help='Listening address', default="0.0.0.0")
        self.parser.add_argument('--p', help='Listening port')
        self.parser.add_argument('--t', help='Target host/ip', required=True)        
        self.parser.add_argument('--tp', help='Target port', required=True)            
        self.parser.add_argument('--s', help='SOCKS5 server host/ip', default="localhost")          
        self.parser.add_argument('--sp', help='SOCKS5 server port', default="1080")              
                     
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
    