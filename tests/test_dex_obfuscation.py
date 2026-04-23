"""Tests for drake_x.dex.obfuscation — obfuscation heuristic analysis."""

from __future__ import annotations

import pytest

from drake_x.dex.obfuscation import analyze_obfuscation
from drake_x.models.dex import (
    DexClassInfo,
    DexFileInfo,
    DexMethodInfo,
    ObfuscationSignal,
)


class TestAnalyzeObfuscation:
    def test_short_identifiers_detected(self) -> None:
        classes = [
            DexClassInfo(class_name=f"com.app.{chr(97 + i)}", package="com.app")
            for i in range(15)
        ]
        methods = [
            DexMethodInfo(
                class_name="com.app.a",
                method_name=chr(97 + i),
                access_flags="public",
            )
            for i in range(25)
        ]
        indicators, score = analyze_obfuscation(classes=classes, methods=methods)
        signals = {i.signal for i in indicators}
        assert ObfuscationSignal.SHORT_IDENTIFIERS in signals
        assert score > 0

    def test_reflection_abuse_detected(self) -> None:
        text = "\n".join([
            "Class.forName(cls);",
            "method.invoke(obj);",
            "getDeclaredMethod(name);",
            "Class.forName(x); Class.forName(y);",
            "m.invoke(a); m.invoke(b);",
        ])
        indicators, score = analyze_obfuscation(smali_text=text)
        signals = {i.signal for i in indicators}
        assert ObfuscationSignal.REFLECTION_ABUSE in signals

    def test_encoded_strings_detected(self) -> None:
        # Strings must be >=20 chars to match the encoded regex
        raw_strings = [
            "SGVsbG8gV29ybGQhIFRoaXM=",
            "dGhpcyBpcyBlbmNvZGVkIGRhdGE=",
            "YW5vdGhlciBiYXNlNjQgZW5jb2RlZA==",
            "c29tZSBtb3JlIGRhdGEgaGVyZSBub3c=",
            "ZXZlbiBtb3JlIGRhdGFhIGFuZCBtb3Jl",
            "bW9yZSBhbmQgbW9yZSBlbmNvZGVkIGRhdGE=",
        ]
        indicators, score = analyze_obfuscation(raw_strings=raw_strings)
        signals = {i.signal for i in indicators}
        assert ObfuscationSignal.ENCODED_STRINGS in signals

    def test_multi_dex_splitting_detected(self) -> None:
        dex_infos = [
            DexFileInfo(filename=f"classes{i}.dex", path=f"/x/classes{i}.dex", class_count=50)
            for i in range(4)
        ]
        indicators, score = analyze_obfuscation(dex_infos=dex_infos)
        signals = {i.signal for i in indicators}
        assert ObfuscationSignal.MULTI_DEX_SPLITTING in signals

    def test_dynamic_loading_detected(self) -> None:
        text = """
        DexClassLoader loader = new DexClassLoader(path, dir, null, parent);
        InMemoryDexClassLoader mem = new InMemoryDexClassLoader(buf, parent);
        cls.loadClass("com.hidden.Payload");
        """
        indicators, score = analyze_obfuscation(java_text=text)
        signals = {i.signal for i in indicators}
        assert ObfuscationSignal.DYNAMIC_LOADING in signals

    def test_identifier_renaming_detected(self) -> None:
        classes = [
            DexClassInfo(class_name=f"com.obf.{chr(97 + i)}", package="com.obf")
            for i in range(10)
        ]
        indicators, score = analyze_obfuscation(classes=classes)
        signals = {i.signal for i in indicators}
        assert ObfuscationSignal.IDENTIFIER_RENAMING in signals

    def test_control_flow_detected(self) -> None:
        smali = "\n".join(["goto :label"] * 600 + ["packed-switch"] * 150)
        indicators, score = analyze_obfuscation(smali_text=smali)
        signals = {i.signal for i in indicators}
        assert ObfuscationSignal.CONTROL_FLOW in signals

    def test_native_bridge_detected(self) -> None:
        text = "System.loadLibrary(\"native\");\nSystem.loadLibrary(\"crypto\");"
        indicators, score = analyze_obfuscation(java_text=text)
        signals = {i.signal for i in indicators}
        assert ObfuscationSignal.NATIVE_BRIDGE in signals

    def test_clean_app_low_score(self) -> None:
        classes = [
            DexClassInfo(class_name="com.myapp.MainActivity", package="com.myapp"),
            DexClassInfo(class_name="com.myapp.Utils", package="com.myapp"),
        ]
        methods = [
            DexMethodInfo(class_name="com.myapp.MainActivity", method_name="onCreate"),
            DexMethodInfo(class_name="com.myapp.Utils", method_name="formatDate"),
        ]
        indicators, score = analyze_obfuscation(classes=classes, methods=methods)
        assert score < 0.2
        assert len(indicators) == 0

    def test_empty_input(self) -> None:
        indicators, score = analyze_obfuscation()
        assert indicators == []
        assert score == 0.0

    def test_score_capped_at_one(self) -> None:
        """Even with all signals, score should not exceed 1.0."""
        classes = [
            DexClassInfo(class_name=f"com.obf.{chr(97 + i)}", package="com.obf")
            for i in range(20)
        ]
        methods = [
            DexMethodInfo(class_name="com.obf.a", method_name=chr(97 + i))
            for i in range(30)
        ]
        dex_infos = [
            DexFileInfo(filename=f"classes{i}.dex", path=f"/x/{i}", class_count=5)
            for i in range(5)
        ]
        text = "\n".join([
            "Class.forName(x);", "m.invoke(y);", "getDeclaredMethod(z);",
            "DexClassLoader l;", "InMemoryDexClassLoader m;",
            "System.loadLibrary(x);", "System.loadLibrary(y);",
        ] * 5)
        smali = "\n".join(["goto :l"] * 600)
        raw_strings = ["SGVsbG8gV29ybGQ="] * 10

        _, score = analyze_obfuscation(
            classes=classes,
            methods=methods,
            dex_infos=dex_infos,
            raw_strings=raw_strings,
            smali_text=smali,
            java_text=text,
        )
        assert score <= 1.0
