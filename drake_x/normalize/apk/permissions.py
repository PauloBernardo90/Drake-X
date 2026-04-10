"""Parse and classify Android permissions."""

from __future__ import annotations

import re

from ...models.apk import ApkPermission

# Permissions that individually warrant analyst attention.
SUSPICIOUS_PERMISSIONS: set[str] = {
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
}

DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
}


def parse_permissions(badging_stdout: str) -> list[ApkPermission]:
    """Extract permissions from ``aapt dump badging`` output."""
    perms: list[ApkPermission] = []
    seen: set[str] = set()
    for m in re.finditer(r"uses-permission:\s+name='([^']+)'", badging_stdout):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        perms.append(ApkPermission(
            name=name,
            is_dangerous=name in DANGEROUS_PERMISSIONS,
            is_suspicious=name in SUSPICIOUS_PERMISSIONS,
        ))
    return perms


def flag_suspicious(permissions: list[ApkPermission]) -> list[ApkPermission]:
    """Return only the permissions that are suspicious or dangerous."""
    return [p for p in permissions if p.is_suspicious or p.is_dangerous]
