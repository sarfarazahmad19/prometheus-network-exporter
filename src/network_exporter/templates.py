import io

cisco_drops_tmpl = b"""Value INTERFACE (\S+)
Value RX_PKTS (\d+)
Value TX_PKTS (\d+)

Start
  ^\s*Interface\s+Rx Pkts\s+Tx Pkts -> InterfaceLines

InterfaceLines
  ^\s*${INTERFACE}\s+${RX_PKTS}\s+${TX_PKTS}\s*$$ -> Record
"""

# upstream : https://github.com/networktocode/ntc-templates/blob/master/ntc_templates/templates/cisco_ios_show_interfaces.textfsm
cisco_show_interface_tmpl = b"""Value Required INTERFACE (\S+)
Value LINK_STATUS (.+?)
Value PROTOCOL_STATUS (.+?)
Value HARDWARE_TYPE ([\w \-]+)
Value MAC_ADDRESS ([a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4})
Value BIA ([a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4})
Value DESCRIPTION (.+?)
Value IP_ADDRESS (\d+\.\d+\.\d+\.\d+)
Value PREFIX_LENGTH (\d+)
Value MTU (\d+)
Value DUPLEX (([Ff]ull|[Aa]uto|[Hh]alf|[Aa]-).*?)
Value SPEED (.*?)
Value MEDIA_TYPE (\S+.*)
Value BANDWIDTH (\d+\s+\w+)
Value DELAY (\d+\s+\S+)
Value ENCAPSULATION (.+?)
Value LAST_INPUT (.+?)
Value LAST_OUTPUT (.+?)
Value LAST_OUTPUT_HANG (.+?)
Value QUEUE_STRATEGY (.+)
Value INPUT_RATE (\d+)
Value OUTPUT_RATE (\d+)
Value INPUT_PPS (\d+)
Value OUTPUT_PPS (\d+)
Value INPUT_PACKETS (\d+)
Value OUTPUT_PACKETS (\d+)
Value RUNTS (\d+)
Value GIANTS (\d+)
Value INPUT_ERRORS (\d+)
Value CRC (\d+)
Value FRAME (\d+)
Value OVERRUN (\d+)
Value ABORT (\d+)
Value OUTPUT_ERRORS (\d+)
Value VLAN_ID (\d+)
Value VLAN_ID_INNER (\d+)
Value VLAN_ID_OUTER (\d+)
Value QUEUE_SIZE (\d+)
Value QUEUE_MAX (\d+) 
Value QUEUE_DROPS (\d+)
Value QUEUE_FLUSHES (\d+)
Value QUEUE_OUTPUT_DROPS (\d+)

Start
  ^\S+\s+is\s+.+?,\s+line\s+protocol.*$$ -> Continue.Record
  ^${INTERFACE}\s+is\s+${LINK_STATUS},\s+line\s+protocol\s+is\s+${PROTOCOL_STATUS}\s*$$
  ^\s+Hardware\s+is\s+${HARDWARE_TYPE} -> Continue
  ^.+address\s+is\s+${MAC_ADDRESS}\s+\(bia\s+${BIA}\)\s*$$
  ^\s+Description:\s+${DESCRIPTION}\s*$$
  ^\s+Internet\s+address\s+is\s+${IP_ADDRESS}\/${PREFIX_LENGTH}\s*$$
  ^\s+MTU\s+${MTU}.*BW\s+${BANDWIDTH}.*DLY\s+${DELAY},\s*$$
  ^\s+Encapsulation\s+${ENCAPSULATION}, Vlan ID\s+${VLAN_ID}.+$$
  ^\s+Encapsulation\s+${ENCAPSULATION}, outer ID\s+${VLAN_ID_OUTER}, inner ID\s+${VLAN_ID_INNER}.+$$
  ^\s+Encapsulation\s+${ENCAPSULATION},.+$$
  ^\s+Last\s+input\s+${LAST_INPUT},\s+output\s+${LAST_OUTPUT},\s+output\s+hang\s+${LAST_OUTPUT_HANG}\s*$$
  ^\s+Input\s+queue:\s+${QUEUE_SIZE}\/${QUEUE_MAX}\/${QUEUE_DROPS}\/${QUEUE_FLUSHES}\s+\(size\/max\/drops\/flushes\);\s+Total output\s+drops:\s+${QUEUE_OUTPUT_DROPS}\s*$$
  ^\s+Queueing\s+strategy:\s+${QUEUE_STRATEGY}\s*$$
  ^\s+${DUPLEX},\s+${SPEED},.+media\stype\sis\s${MEDIA_TYPE}$$
  ^\s+${DUPLEX},\s+${SPEED},.+TX/FX$$
  ^\s+${DUPLEX},\s+${SPEED}$$
  ^.*input\s+rate\s+${INPUT_RATE}\s+\w+/sec,\s+${INPUT_PPS}\s+packets.+$$
  ^.*output\s+rate\s+${OUTPUT_RATE}\s+\w+/sec,\s+${OUTPUT_PPS}\s+packets.+$$
  ^\s+${INPUT_PACKETS}\s+packets\s+input,\s+\d+\s+bytes,\s+\d+\s+no\s+buffer\s*$$
  ^\s+${RUNTS}\s+runts,\s+${GIANTS}\s+giants,\s+\d+\s+throttles\s*$$
  ^\s+${INPUT_ERRORS}\s+input\s+errors,\s+${CRC}\s+CRC,\s+${FRAME}\s+frame,\s+${OVERRUN}\s+overrun,\s+\d+\s+ignored\s*$$
  ^\s+${INPUT_ERRORS}\s+input\s+errors,\s+${CRC}\s+CRC,\s+${FRAME}\s+frame,\s+${OVERRUN}\s+overrun,\s+\d+\s+ignored,\s+${ABORT}\s+abort\s*$$
  ^\s+${OUTPUT_PACKETS}\s+packets\s+output,\s+\d+\s+bytes,\s+\d+\s+underruns\s*$$
  ^\s+${OUTPUT_ERRORS}\s+output\s+errors,\s+\d+\s+collisions,\s+\d+\s+interface\s+resets\s*$$
  # Capture time-stamp if vty line has command time-stamping turned on
  ^Load\s+for\s+
  ^Time\s+source\s+is
"""

cisco_show_policy_map_interface_tmpl = b"""Value SERVICE_POLICY_INPUT (\S+)
Value CLASS_MAP (\S+)
Value CIR_BPS (\d+)

Start
  ^\s*Service-policy input: ${SERVICE_POLICY_INPUT}$$
  ^\s*Class-map:\s${CLASS_MAP}\s.*?$$  
  ^\s*police:\s.*$$ 
  ^\s*cir\s${CIR_BPS}\sbps,.*$$ -> Record
"""

cisco_show_processes_cpu_tmpl = b"""Value CPU_USAGE_5_SEC (\d+)
Value CPU_INTERRUPTION_5_SEC (\d+)
Value CPU_USAGE_1_MIN (\d+)
Value CPU_USAGE_5_MIN (\d+)

Start
  ^\s*CPU\s+utilization\s+for\s+five\s+seconds:\s+${CPU_USAGE_5_SEC}%/${CPU_INTERRUPTION_5_SEC}%;\s+one\s+minute:\s+${CPU_USAGE_1_MIN}%;\s+five\s+minutes:\s+${CPU_USAGE_5_MIN}%\s*$$ -> Record
  ^\s*$$
  ^. -> Error
"""

cisco_show_processes_memory_tmpl = b"""Value MEMORY_TOTAL (\d+)
Value MEMORY_USED (\d+)
Value MEMORY_FREE (\d+)

Start
  ^Processor\s+Pool\s+Total:\s+${MEMORY_TOTAL}\s+Used:\s+${MEMORY_USED}\s+Free:\s+${MEMORY_FREE}
  ^\s*$$
  ^. -> Error
"""


class classproperty:
    """
    We do this because conventional classproperties i.e. using @classmethod and @property together, is deprecated now and will not work from Python3.13 onwards
    """

    def __init__(self, method):
        self.method = method

    def __get__(self, obj, cls=None):
        if cls is None:
            cls = type(obj)
        return self.method(cls)


class CiscoTemplates:
    @classmethod
    @classproperty
    def drops(cls):
        return io.BytesIO(cisco_drops_tmpl)

    @classmethod
    @classproperty
    def show_interface(cls):
        return io.BytesIO(cisco_show_interface_tmpl)

    @classmethod
    @classproperty
    def show_policy_map_interface(cls):
        return io.BytesIO(cisco_show_policy_map_interface_tmpl)

    @classmethod
    @classproperty
    def show_processes_cpu(cls):
        # Expect this `CPU utilization for five seconds: 0%/0%; one minute: 1%; five minutes: 1%`
        return io.BytesIO(cisco_show_processes_cpu_tmpl)

    @classmethod
    @classproperty
    def show_processes_memory(cls):
        # Expect this `CPU utilization for five seconds: 0%/0%; one minute: 1%; five minutes: 1%`
        return io.BytesIO(cisco_show_processes_memory_tmpl)
