from prometheus_client import CollectorRegistry, Gauge


class CiscoRegistry(CollectorRegistry):
    def __init__(self):
        super().__init__()
        self.app_version = Gauge(
            "network_exporter_version", "Gauge reporting version of network exporter", ["podname"], registry=self
        )
        self.cisco_system_resource_metric = Gauge(
            "cisco_system_resource",
            "Gauge for various system resources cpu, mem_used, mem_free",
            ["type", "hostname"],
            registry=self,
        )
        self.cisco_interface_oper_status = Gauge(
            "interface_oper_status",
            "Gauge for interface status, whether up(1) or down(0)",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_admin_status = Gauge(
            "interface_admin_status",
            "Gauge representating if Interface's are *admin* up(1) or down(0)",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_input_packets = Gauge(
            "interface_input_packets",
            "Gauge counting input packets",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_output_packets = Gauge(
            "interface_output_packets",
            "Gauge counting output packets",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_input_errors = Gauge(
            "interface_input_errors",
            "Gauge counting input packet errors",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_output_errors = Gauge(
            "interface_output_errors",
            "Gauge counting output packet errors",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_input_rate = Gauge(
            "interface_input_rate_bps",
            "Gauge representing 5 min input rate from show interfaces",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_output_rate = Gauge(
            "interface_output_rate_bps",
            "Gauge representing 5 min output rate from show interfaces",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_input_drops = Gauge(
            "interface_input_drops",
            "Gauge counting input packet drops",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_output_drops = Gauge(
            "interface_output_drops",
            "Gauge counting output packet drops",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_qos_bps = Gauge(
            "interface_qos_bps",
            "Gauge QoS limit on the interface",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname"],
            registry=self,
        )
        self.cisco_interface_qos_policy_name = Gauge(
            "interface_qos_policy_name",
            "Gauge QoS limit on the interface",
            ["interface", "ipaddress", "description", "side", "type", "name", "hostname", "classmap"],
            registry=self,
        )
        self.cisco_connection_established_timestamp = Gauge(
            "cisco_connection_timestamp",
            "Gauge - timestamp when ssh connection was last established",
            ["hostname", "podname", "module"],
            registry=self,
        )


class PanosRegistry(CollectorRegistry):
    def __init__(self):
        super().__init__()
        self.app_version = Gauge(
            "network_exporter_version", "Gauge reporting version of network exporter", [], registry=self
        )
        self.panos_hitcount_metric = Gauge(
            "panos_security_rule_hit_count",
            "Hit Count (counter) for firewall's security rules",
            ["name"],
            registry=self,
        )
        self.panos_system_resource_metric = Gauge(
            "panos_system_resource",
            "Gauge for various system resources cpu, mem_used, mem_free",
            ["type"],
            registry=self,
        )
        self.panos_uptime_metric = Gauge("panos_uptime_days", "System uptime", registry=self)
