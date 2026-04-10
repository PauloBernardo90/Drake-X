"""Parse ``aapt dump badging`` output into APK metadata."""

from __future__ import annotations

import re

from ...models.apk import ApkMetadata


def parse_badging(stdout: str) -> ApkMetadata:
    """Extract package name, version, SDK versions from aapt badging output."""
    meta = ApkMetadata()

    m = re.search(r"package:\s+name='([^']*)'", stdout)
    if m:
        meta.package_name = m.group(1)

    m = re.search(r"versionCode='([^']*)'", stdout)
    if m:
        meta.version_code = m.group(1)

    m = re.search(r"versionName='([^']*)'", stdout)
    if m:
        meta.version_name = m.group(1)

    m = re.search(r"sdkVersion:'(\d+)'", stdout)
    if m:
        meta.min_sdk = m.group(1)

    m = re.search(r"targetSdkVersion:'(\d+)'", stdout)
    if m:
        meta.target_sdk = m.group(1)

    m = re.search(r"launchable-activity:\s+name='([^']*)'", stdout)
    if m:
        meta.main_activity = m.group(1)

    return meta
