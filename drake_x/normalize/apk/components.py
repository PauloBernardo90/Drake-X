"""Parse Android components from aapt badging or manifest XML."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ...models.apk import ApkComponent, ComponentType


def parse_components(badging_stdout: str) -> list[ApkComponent]:
    """Extract Activities, Services, Receivers from aapt badging output."""
    components: list[ApkComponent] = []

    for m in re.finditer(r"(?:launchable-)?activity(?:-alias)?:\s+name='([^']+)'", badging_stdout):
        components.append(ApkComponent(
            component_type=ComponentType.ACTIVITY,
            name=m.group(1),
        ))

    return components


def parse_manifest_xml(xml_text: str) -> list[ApkComponent]:
    """Parse components from a decoded AndroidManifest.xml string.

    This handles the XML produced by ``apktool d`` (plain XML), not the
    binary format.
    """
    components: list[ApkComponent] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return components

    ns = "{http://schemas.android.com/apk/res/android}"
    app = root.find("application")
    if app is None:
        return components

    type_map = {
        "activity": ComponentType.ACTIVITY,
        "service": ComponentType.SERVICE,
        "receiver": ComponentType.RECEIVER,
        "provider": ComponentType.PROVIDER,
    }

    for tag, ctype in type_map.items():
        for elem in app.findall(tag):
            name = elem.get(f"{ns}name", "")
            exported_raw = elem.get(f"{ns}exported", "")
            exported = exported_raw.lower() == "true"

            intent_filters: list[str] = []
            for intent in elem.findall("intent-filter"):
                for action in intent.findall("action"):
                    action_name = action.get(f"{ns}name", "")
                    if action_name:
                        intent_filters.append(action_name)
                # If the component has an intent-filter and exported is not
                # explicitly set, Android defaults to exported=true.
                if not exported_raw and intent_filters:
                    exported = True

            if name:
                components.append(ApkComponent(
                    component_type=ctype,
                    name=name,
                    exported=exported,
                    intent_filters=intent_filters,
                ))

    return components
