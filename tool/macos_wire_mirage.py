#!/usr/bin/env python3
"""Wires Mirage.xcframework + VpnPlugin.swift into macos/Runner.xcodeproj.

Adds the vendored apple/Frameworks/Mirage.xcframework to the Runner target's
Frameworks phase and its "Bundle Framework" embed phase (CodeSignOnCopy),
adds VpnPlugin.swift to Sources, and sets FRAMEWORK_SEARCH_PATHS on the
Runner build configs.

Usage:  python3 tool/macos_wire_mirage.py
Idempotent: exits 1 if already applied.
"""
import sys
from pathlib import Path

PBX = Path(__file__).resolve().parent.parent / "macos" / "Runner.xcodeproj" / "project.pbxproj"

U = {
    "mirage":   "5BB0000000000000000000A1",
    "plugin":   "5BB0000000000000000000A2",
    "bf_fw":    "5BB0000000000000000000E1",
    "bf_embed": "5BB0000000000000000000E2",
    "bf_src":   "5BB0000000000000000000E3",
}

FRAMEWORKS_GROUP = "D73912EC22F37F3D000D13A0"
RUNNER_GROUP = "33FAB671232836740065AC1E"
RUNNER_SOURCES = "33CC10E92044A3C60003C045"
RUNNER_FRAMEWORKS = "33CC10EA2044A3C60003C045"
BUNDLE_FRAMEWORK = "33CC110E2044A8840003C045"


def insert_before_end(text: str, section: str, block: str) -> str:
    marker = f"/* End {section} section */"
    assert marker in text, f"missing section {section}"
    return text.replace(marker, block + marker)


def main() -> int:
    text = PBX.read_text()
    if "Mirage.xcframework" in text:
        print("Mirage already wired — refusing to double-apply", file=sys.stderr)
        return 1

    text = insert_before_end(text, "PBXBuildFile", f"""\
\t\t{U["bf_fw"]} /* Mirage.xcframework in Frameworks */ = {{isa = PBXBuildFile; fileRef = {U["mirage"]} /* Mirage.xcframework */; }};
\t\t{U["bf_embed"]} /* Mirage.xcframework in Bundle Framework */ = {{isa = PBXBuildFile; fileRef = {U["mirage"]} /* Mirage.xcframework */; settings = {{ATTRIBUTES = (CodeSignOnCopy, RemoveHeadersOnCopy, ); }}; }};
\t\t{U["bf_src"]} /* VpnPlugin.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {U["plugin"]} /* VpnPlugin.swift */; }};
""")

    text = insert_before_end(text, "PBXFileReference", f"""\
\t\t{U["mirage"]} /* Mirage.xcframework */ = {{isa = PBXFileReference; lastKnownFileType = wrapper.xcframework; name = Mirage.xcframework; path = "../apple/Frameworks/Mirage.xcframework"; sourceTree = "<group>"; }};
\t\t{U["plugin"]} /* VpnPlugin.swift */ = {{isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.swift; path = VpnPlugin.swift; sourceTree = "<group>"; }};
""")

    fw_grp_old = """\
		D73912EC22F37F3D000D13A0 /* Frameworks */ = {
			isa = PBXGroup;
			children = (
			);"""
    assert fw_grp_old in text
    text = text.replace(fw_grp_old, fw_grp_old.replace(
        "children = (\n\t\t\t);",
        f'children = (\n\t\t\t\t{U["mirage"]} /* Mirage.xcframework */,\n\t\t\t);'))

    runner_grp_old = """\
				33CC10F02044A3C60003C045 /* AppDelegate.swift */,
				33CC11122044BFA00003C045 /* MainFlutterWindow.swift */,"""
    assert runner_grp_old in text
    text = text.replace(runner_grp_old, runner_grp_old +
        f"\n\t\t\t\t{U['plugin']} /* VpnPlugin.swift */,")

    runner_fw_old = f"""\
\t\t{RUNNER_FRAMEWORKS} /* Frameworks */ = {{
\t\t\tisa = PBXFrameworksBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t);"""
    assert runner_fw_old in text
    text = text.replace(runner_fw_old, runner_fw_old.replace(
        "files = (\n\t\t\t);",
        f'files = (\n\t\t\t\t{U["bf_fw"]} /* Mirage.xcframework in Frameworks */,\n\t\t\t);'))

    bundle_fw_old = f"""\
\t\t{BUNDLE_FRAMEWORK} /* Bundle Framework */ = {{
\t\t\tisa = PBXCopyFilesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tdstPath = "";
\t\t\tdstSubfolderSpec = 10;
\t\t\tfiles = (
\t\t\t);"""
    assert bundle_fw_old in text
    text = text.replace(bundle_fw_old, bundle_fw_old.replace(
        "files = (\n\t\t\t);",
        f'files = (\n\t\t\t\t{U["bf_embed"]} /* Mirage.xcframework in Bundle Framework */,\n\t\t\t);'))

    runner_src_old = """\
				33CC11132044BFA00003C045 /* MainFlutterWindow.swift in Sources */,
				33CC10F12044A3C60003C045 /* AppDelegate.swift in Sources */,"""
    assert runner_src_old in text
    text = text.replace(runner_src_old, runner_src_old +
        f"\n\t\t\t\t{U['bf_src']} /* VpnPlugin.swift in Sources */,")

    # Runner build configs are the ones carrying CODE_SIGN_ENTITLEMENTS.
    ent = "CODE_SIGN_ENTITLEMENTS = Runner/"
    count = text.count(ent)
    assert count == 3, f"expected 3 Runner entitlement settings, found {count}"
    text = text.replace(
        ent,
        """FRAMEWORK_SEARCH_PATHS = (
					"$(inherited)",
					"$(SRCROOT)/../apple/Frameworks",
				);
				CODE_SIGN_ENTITLEMENTS = Runner/""",
    )

    PBX.write_text(text)
    print("Mirage.xcframework + VpnPlugin wired into macos/Runner.xcodeproj")
    return 0


if __name__ == "__main__":
    sys.exit(main())
