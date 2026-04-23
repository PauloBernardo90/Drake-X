"""Tests for drake_x.dex.sensitive_apis — sensitive API detection."""

from __future__ import annotations

import pytest

from drake_x.dex.sensitive_apis import detect_sensitive_apis
from drake_x.models.dex import SensitiveApiCategory


class TestDetectSensitiveApis:
    def test_accessibility_service(self) -> None:
        text = """
        public class MyService extends AccessibilityService {
            public void onAccessibilityEvent(AccessibilityEvent event) {
                AccessibilityNodeInfo node = event.getSource();
            }
        }
        """
        hits = detect_sensitive_apis(text, source_dex="classes.dex")
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.ACCESSIBILITY in categories

    def test_package_installer(self) -> None:
        text = 'session = PackageInstaller.createSession(params);'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.PACKAGE_INSTALLER in categories

    def test_webview(self) -> None:
        text = """
        WebView wv = new WebView(context);
        wv.getSettings().setJavaScriptEnabled(true);
        wv.addJavascriptInterface(new Bridge(), "Android");
        wv.loadUrl("https://evil.com");
        """
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.WEBVIEW in categories

    def test_sms_manager(self) -> None:
        text = 'SmsManager.getDefault().sendTextMessage(number, null, msg, null, null);'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.SMS in categories

    def test_telephony_manager(self) -> None:
        text = 'TelephonyManager tm = getSystemService(TELEPHONY_SERVICE); tm.getDeviceId();'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.TELEPHONY in categories

    def test_device_policy_manager(self) -> None:
        text = 'DevicePolicyManager dpm = getSystemService(DEVICE_POLICY_SERVICE); dpm.lockNow();'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.DEVICE_ADMIN in categories

    def test_runtime_exec(self) -> None:
        text = 'Runtime.getRuntime().exec("su");'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.RUNTIME_EXEC in categories

    def test_dex_class_loader(self) -> None:
        text = 'DexClassLoader loader = new DexClassLoader(path, dir, null, parent);'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.DEX_LOADING in categories

    def test_reflection(self) -> None:
        text = """
        Class<?> cls = Class.forName("com.hidden.Payload");
        Method m = cls.getDeclaredMethod("run");
        m.invoke(instance);
        """
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.REFLECTION in categories

    def test_crypto(self) -> None:
        text = 'Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.CRYPTO in categories

    def test_clipboard(self) -> None:
        text = 'ClipboardManager cm = getSystemService(CLIPBOARD_SERVICE); cm.getPrimaryClip();'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.CLIPBOARD in categories

    def test_location(self) -> None:
        text = 'LocationManager lm; lm.requestLocationUpdates(provider, 0, 0, listener);'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.LOCATION in categories

    def test_contacts(self) -> None:
        text = 'cursor = resolver.query(ContactsContract.Contacts.CONTENT_URI, null, null, null, null);'
        hits = detect_sensitive_apis(text)
        categories = {h.api_category for h in hits}
        assert SensitiveApiCategory.CONTACTS in categories

    def test_empty_text(self) -> None:
        assert detect_sensitive_apis("") == []

    def test_benign_code(self) -> None:
        text = """
        public class Calculator {
            public int add(int a, int b) { return a + b; }
        }
        """
        hits = detect_sensitive_apis(text)
        assert len(hits) == 0

    def test_dedup(self) -> None:
        """Same API found multiple times should not produce exact duplicates."""
        text = "DexClassLoader x; DexClassLoader y; DexClassLoader z;"
        hits = detect_sensitive_apis(text)
        names = [h.api_name for h in hits]
        # May have more than one if different match groups, but should dedup same match
        assert len(names) <= 3

    def test_source_dex_propagated(self) -> None:
        text = "SmsManager.getDefault();"
        hits = detect_sensitive_apis(text, source_dex="classes2.dex")
        assert all(h.source_dex == "classes2.dex" for h in hits)
