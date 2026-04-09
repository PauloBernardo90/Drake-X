"""Parse nmap XML output (``-oX -``) into a structured artifact."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from ..models.artifact import Artifact
from ..models.tool_result import ToolResult


def normalize_nmap(result: ToolResult) -> Artifact:
    payload: dict[str, Any] = {"hosts": []}
    notes: list[str] = []
    confidence = 0.6

    if not result.stdout.strip():
        notes.append("empty stdout from nmap")
        return Artifact(
            tool_name="nmap",
            kind="nmap.ports",
            payload=payload,
            confidence=0.0,
            notes=notes,
            raw_command=result.command,
        )

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        return Artifact(
            tool_name="nmap",
            kind="nmap.unparsed",
            payload={"reason": str(exc)},
            confidence=0.0,
            notes=["nmap XML parse error"],
            raw_command=result.command,
            raw_stdout_excerpt=result.stdout[:1000],
        )

    for host_el in root.findall("host"):
        addresses: list[dict[str, str]] = []
        for addr_el in host_el.findall("address"):
            addresses.append(
                {
                    "addr": addr_el.attrib.get("addr", ""),
                    "type": addr_el.attrib.get("addrtype", ""),
                }
            )

        hostnames: list[str] = []
        for hn in host_el.findall("./hostnames/hostname"):
            name = hn.attrib.get("name")
            if name:
                hostnames.append(name)

        ports: list[dict[str, Any]] = []
        for p in host_el.findall("./ports/port"):
            state_el = p.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            service_el = p.find("service")
            entry: dict[str, Any] = {
                "port": int(p.attrib.get("portid", "0") or 0),
                "protocol": p.attrib.get("protocol", "tcp"),
                "service": service_el.attrib.get("name") if service_el is not None else None,
                "product": service_el.attrib.get("product") if service_el is not None else None,
                "version": service_el.attrib.get("version") if service_el is not None else None,
                "extrainfo": service_el.attrib.get("extrainfo") if service_el is not None else None,
            }
            ports.append(entry)

        host_status_el = host_el.find("status")
        host_status = host_status_el.attrib.get("state", "unknown") if host_status_el is not None else "unknown"

        payload["hosts"].append(
            {
                "status": host_status,
                "addresses": addresses,
                "hostnames": hostnames,
                "open_ports": ports,
            }
        )

    open_count = sum(len(h.get("open_ports", [])) for h in payload["hosts"])
    payload["open_port_count"] = open_count
    if open_count > 0:
        confidence = 0.9
    elif payload["hosts"]:
        confidence = 0.7
        notes.append("host(s) responded but no open ports detected")
    else:
        notes.append("no hosts in scan output")

    return Artifact(
        tool_name="nmap",
        kind="nmap.ports",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=result.stdout[:2000],
    )
