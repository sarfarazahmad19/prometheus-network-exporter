import re
from decimal import Decimal
from typing import Dict


class PanosParser:
    @staticmethod
    def show_system_resources(cmd_out: str):
        cpu_regex = re.compile(r".*\%Cpu.*, ([\d\.]+) .*id")
        cpu_match = cpu_regex.search(cmd_out)

        mem_regex = re.compile(
            r".*?MiB Mem.*?(\S+) total.*? (\S+) free.*? (\S+) used.*? (\S+) buff/cache.*?\n.*?MiB Swap.*? (\S+) total.*? (\S+) free.*? (\S+) used.*? (\S+) avail Mem",
            re.DOTALL,  # This allows matching across newlines
        )
        mem_match = mem_regex.search(cmd_out)

        if not cpu_match:
            raise RuntimeError("Error parsing output of `show system resources` for cpu usage.")
        if not mem_match:
            raise RuntimeError("Error parsing output of `show system resources` for memory usage.")

        return {
            "cpu_used": 100 - Decimal(cpu_match.group(1)),
            "mem_total_megabytes": float(mem_match.group(1)),
            "mem_free_megabytes": float(mem_match.group(2)),
            "mem_avail_megabytes": float(
                mem_match.group(8)
            ),  # Available memory from the "avail Mem" field out of show resources
        }


class CiscoParser:
    @staticmethod
    def description(description: str, key: str) -> Dict[str, str]:
        """
        Splits description /env:dev/side:a/type:member/name:strongtrader200/ into a dict.
        """
        description_dict = {i.split(":")[0]: i.split(":")[1] for i in description.split("/")[1:-1]}
        return description_dict.get(key, "")
