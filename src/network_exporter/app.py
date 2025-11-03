import importlib.metadata
import json
import logging
import os
import re
import socket
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from functools import partial
from ipaddress import IPv4Address
from typing import Tuple

import panos.firewall
import panos.policies
import textfsm
import xmltodict
from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from prometheus_fastapi_instrumentator import Instrumentator, metrics

from network_exporter.connection import CiscoConnection, PanosConnection
from network_exporter.exceptions import ParseException
from network_exporter.parsers import CiscoParser, PanosParser
from network_exporter.registries import CiscoRegistry, PanosRegistry
from network_exporter.templates import CiscoTemplates

logger = logging.getLogger("uvicorn.error")

REQUIRED_ENVVARS = [f"{type}_{key}" for type in ["PALO", "CISCO"] for key in ["USERNAME", "PASSWORD"]]
SECRETS_MAP = {
    "panos": {"username": "PALO_USERNAME", "password": "PALO_PASSWORD"},
    "cisco": {"username": "CISCO_USERNAME", "password": "CISCO_PASSWORD"},
}

VERSION = importlib.metadata.version(__package__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    instrumentator.expose(app)
    for var in REQUIRED_ENVVARS:
        if var not in os.environ:
            raise RuntimeError(f"Required envvars `{var}` is not set.")

    app.state.cisco_connections = {}
    yield
    logger.info("Shutting down...")


app = FastAPI(lifespan=lifespan)
instrumentator = Instrumentator().instrument(app)
instrumentator.add(
    metrics.latency(
        buckets=(1, 3, 5), should_include_handler=True, should_include_method=False, should_include_status=True
    )
).add(
    metrics.request_size(
        should_include_handler=True,
        should_include_method=False,
        should_include_status=True,
    )
).add(
    metrics.response_size(
        should_include_handler=True,
        should_include_method=False,
        should_include_status=True,
    )
)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    logger.info("%s:%s - Request took %0.3fs seconds to serve", request.client.host, request.client.port, process_time)
    return response


def _lookup_creds(module: str) -> Tuple[str]:
    user_envvar, pass_envvar = (
        SECRETS_MAP[module]["username"],
        SECRETS_MAP[module]["password"],
    )
    return (os.environ[user_envvar], os.environ[pass_envvar])


def _measure_call(c: Callable):
    start = time.time()
    result = c()
    end = time.time()
    return result, end - start


@app.get("/ready")
def readiness_probe():
    return


@app.get("/debug")
def debug(request: Request):
    return {
        "active_cisco_connections": [str(conn) for conn in app.state.cisco_connections.values()],
        "active_cisco_ping_connections": [str(conn) for conn in app.state.cisco_ping_connections.values()],
    }


def _render_panos(request: Request, username: str, password: str, target: IPv4Address):
    registry = PanosRegistry()
    with PanosConnection(hostname=str(target), username=username, password=password) as fw:
        registry.app_version.set(VERSION)
        rule_bases, time_taken = _measure_call(partial(panos.policies.Rulebase.refreshall, parent=fw))
        logger.info(
            "%s:%s - RuleBaseRefresh - Took %0.3fs",
            request.client.host,
            request.client.port,
            time_taken,
        )
        # assert that all securityRules live under a single Rulebase
        assert len(rule_bases) == 1

        # get hitcount root
        hitcount_root, time_taken = _measure_call(partial(rule_bases[0].opstate.hit_count.refresh, style="security"))
        logger.info(
            "%s:%s - HitCountRefresh - Took %0.3fs",
            request.client.host,
            request.client.port,
            time_taken,
        )

        for sec_rule_name, sec_rule_hit_count_obj in hitcount_root.items():
            registry.panos_hitcount_metric.labels(name=sec_rule_name).set(sec_rule_hit_count_obj.hit_count)

        show_system_resources_output, time_taken = _measure_call(partial(fw.op, cmd="show system resources", xml=True))
        logger.info(
            "%s:%s - ShowSystemResource - Took %0.3fs",
            request.client.host,
            request.client.port,
            time_taken,
        )
        cmd_out = xmltodict.parse(show_system_resources_output)["response"]["result"]
        resources = PanosParser.show_system_resources(cmd_out)
        for metric, metric_value in resources.items():
            registry.panos_system_resource_metric.labels(metric).set(metric_value)

        uptime_cmd_out, time_taken = _measure_call(partial(fw.op, cmd="show system info", xml=True))
        uptime_match = re.search(r"([\d]+) days,.*", uptime_cmd_out.decode("utf-8"))
        uptime_days = 0
        if uptime_match:
            uptime_days = uptime_match.groups()[0]
        registry.panos_uptime_metric.set(uptime_days)
    return Response(content=generate_latest(registry), media_type=CONTENT_TYPE_LATEST)


def _convert_to_bool(key):
    "up is 1, everything else is 0"
    if key.lower() == "up":
        return True
    return False


def _render_cisco(request: Request, connection: CiscoConnection):
    registry = CiscoRegistry()
    # Collect device hostname using `show version`
    show_version = connection.send_command_cached("show version")
    podname = socket.gethostname()
    logger.info(
        "%s:%s - `show version` parsed output %s",
        request.client.host,
        request.client.port,
        json.dumps(show_version),
    )
    assert "show_version", "Failure fetching or parsing `show version`"
    hostname = show_version[0]["hostname"]

    # Collect network-exporter version
    if hostname:
        registry.app_version.labels(podname=podname).set(VERSION)

    # Collect and parse CPU usage
    cpu_usage = connection.send_command("show processes cpu", use_textfsm=False)
    # Take the first line in all output that starts with "CPU"
    cpu_usage_line = next((line for line in cpu_usage.splitlines() if line.startswith("CPU")), None)
    cpu_usage_parsed = {}
    cpu_usage_parsed = textfsm.TextFSM(CiscoTemplates.show_processes_cpu).ParseTextToDicts(cpu_usage_line)
    if not cpu_usage_parsed:
        raise ParseException("Failed to parse output of `show processes cpu` using textfsm template.")
    logger.info(
        "%s:%s - `show process cpu` parsed output %s",
        request.client.host,
        request.client.port,
        json.dumps(cpu_usage_parsed),
    )
    cpu_used_1m_pct, cpu_used_5m_pct = cpu_usage_parsed[0]["CPU_USAGE_1_MIN"], cpu_usage_parsed[0]["CPU_USAGE_5_MIN"]
    registry.cisco_system_resource_metric.labels(**{"type": "cpu_used_1m_pct", "hostname": hostname}).set(
        cpu_used_1m_pct
    )
    registry.cisco_system_resource_metric.labels(**{"type": "cpu_used_5m_pct", "hostname": hostname}).set(
        cpu_used_5m_pct
    )

    # Collect and parse memory usage
    mem_usage = connection.send_command("show processes memory", use_textfsm=False)
    mem_usage_parsed = {}
    mem_usage_line = next((line for line in mem_usage.splitlines() if line.startswith("Processor Pool")), None)
    mem_usage_parsed = textfsm.TextFSM(CiscoTemplates.show_processes_memory).ParseTextToDicts(mem_usage_line)
    if not mem_usage_parsed:
        raise ParseException("Failed to parse output of `show processes memory` using textfsm template.")
    logger.info(
        "%s:%s - `show process memory` parsed output %s",
        request.client.host,
        request.client.port,
        json.dumps(mem_usage_parsed),
    )
    mem_total, mem_used, mem_free = (
        mem_usage_parsed[0]["MEMORY_TOTAL"],
        mem_usage_parsed[0]["MEMORY_USED"],
        mem_usage_parsed[0]["MEMORY_FREE"],
    )
    registry.cisco_system_resource_metric.labels(**{"type": "mem_used_megabytes", "hostname": hostname}).set(mem_used)
    registry.cisco_system_resource_metric.labels(**{"type": "mem_free_megabytes", "hostname": hostname}).set(mem_free)
    registry.cisco_system_resource_metric.labels(**{"type": "mem_total_megabytes", "hostname": hostname}).set(mem_total)

    # Collect interface stats: operState, adminState, drops, errors
    intr_status_output = connection.send_command("show interface", use_textfsm=False)
    # We do this hack because when you pass use_textfsm=True to netmiko.send_command, it does not render queue_drops or queue_output_drops
    intr_status_tmpl = textfsm.TextFSM(CiscoTemplates.show_interface)
    intr_status_parsed = intr_status_tmpl.ParseTextToDicts(intr_status_output)
    logger.info(
        "%s:%s - `show interface` parsed output %s",
        request.client.host,
        request.client.port,
        json.dumps(intr_status_parsed),
    )
    intr_status = [{k.lower(): v for k, v in r.items()} for r in intr_status_parsed]

    # Collect QoS for Tunnel interfaces.
    intr_tunnel = [intr["interface"] for intr in intr_status if intr["interface"].startswith("Tunnel")]
    intr_tunnel_qos_map = {}

    for intr in intr_tunnel:
        # {'Tunnel10': [{'CLASS_MAP': 'limit64mb', 'SERVICE_POLICY_INPUT': 'limit64mb', 'CIR_BPS': '64000000'}]
        # Note: we need to init template for every interface, otherwise TextFSM collects all outputs i.e. keeps appending.
        intr_tunnel_qos_tmpl = textfsm.TextFSM(CiscoTemplates.show_policy_map_interface)
        policy_map_parsed = intr_tunnel_qos_tmpl.ParseTextToDicts(
            connection.send_command_cached(f"show policy-map interface {intr}")
        )
        logger.info(
            "%s:%s - `show policy-map interface %s` parsed output %s",
            request.client.host,
            request.client.port,
            intr,
            json.dumps(policy_map_parsed),
        )
        if policy_map_parsed:
            intr_tunnel_qos_map[intr] = {}
            intr_tunnel_qos_map[intr]["name"] = policy_map_parsed[0].get("SERVICE_POLICY_INPUT")
            intr_tunnel_qos_map[intr]["bps"] = policy_map_parsed[0].get("CIR_BPS")

    for intr in intr_status:

        def common_labels(intr, hostname):
            description = intr["description"]
            return {
                "hostname": hostname,
                "interface": intr["interface"],
                "ipaddress": intr["ip_address"],
                "description": description,
                "side": CiscoParser.description(description, "side"),
                "type": CiscoParser.description(description, "type"),
                "name": CiscoParser.description(description, "name"),
            }

        labels = common_labels(intr, hostname)

        registry.cisco_interface_oper_status.labels(**labels).set(_convert_to_bool(intr["protocol_status"]))
        registry.cisco_interface_admin_status.labels(**labels).set(_convert_to_bool(intr["link_status"]))
        registry.cisco_interface_input_packets.labels(**labels).set(int(intr["input_packets"]))
        registry.cisco_interface_output_packets.labels(**labels).set(int(intr["output_packets"]))
        registry.cisco_interface_input_errors.labels(**labels).set(int(intr["input_errors"]))
        registry.cisco_interface_output_errors.labels(**labels).set(int(intr["output_errors"]))
        registry.cisco_interface_input_rate.labels(**labels).set(int(intr["input_rate"]))
        registry.cisco_interface_output_rate.labels(**labels).set(int(intr["output_rate"]))
        registry.cisco_interface_input_drops.labels(**labels).set(int(intr["queue_drops"]))
        registry.cisco_interface_output_drops.labels(**labels).set(int(intr["queue_output_drops"]))
        if intr["interface"] in intr_tunnel_qos_map.keys():
            (
                registry.cisco_interface_qos_bps.labels(**labels).set(
                    int(intr_tunnel_qos_map.get(intr["interface"]).get("bps"))
                ),
            )
            qos_labels = labels
            qos_labels["classmap"] = intr_tunnel_qos_map.get(intr["interface"]).get("name")
            registry.cisco_interface_qos_policy_name.labels(**qos_labels).set(int(1))

    registry.cisco_connection_established_timestamp.labels(
        **{"hostname": hostname, "podname": podname, "module": "cisco"}
    ).set(connection.established_time)
    return generate_latest(registry)


@app.get("/probe")
def probe(module: str, target: IPv4Address, request: Request):
    match module:
        case "panos":
            username, password = _lookup_creds(module)
            return _render_panos(request, username, password, target)
        case "cisco":
            if target not in app.state.cisco_connections:
                app.state.cisco_connections[target] = CiscoConnection(
                    username=os.environ["CISCO_USERNAME"], password=os.environ["CISCO_PASSWORD"], device=target
                )
            return Response(
                content=_render_cisco(request, app.state.cisco_connections[target]),
                media_type=CONTENT_TYPE_LATEST,
            )
        case _:
            return Response(
                status_code=400, content="Invalid request. Available modules are `panos` or `cisco`"
            )
