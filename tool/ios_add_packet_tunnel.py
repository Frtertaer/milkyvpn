#!/usr/bin/env python3
"""Adds the PacketTunnel NetworkExtension target to ios/Runner.xcodeproj.

Flutter cannot create app-extension targets, and `xcodeproj` gems are not
available in CI, so this script performs the equivalent of
File > New > Target > Network Extension (packet tunnel) deterministically:

  * PacketTunnel native target (homes.milky.vpn.PacketTunnel) with Sources /
    Frameworks / Resources phases and Debug+Release+Profile configs
  * Runner target: target dependency on PacketTunnel, "Embed App Extensions"
    copy phase (dstSubfolderSpec=13), Mirage.xcframework linked + embedded,
    CODE_SIGN_ENTITLEMENTS + FRAMEWORK_SEARCH_PATHS, bundle id homes.milky.vpn
  * file references for the Swift sources, Info.plist, entitlements, and the
    vendored apple/Frameworks/Mirage.xcframework

Usage:  python3 tool/ios_add_packet_tunnel.py            # apply
        python3 tool/ios_add_packet_tunnel.py --check    # verify only
Idempotent: exits 1 with a message if the target already exists.
"""
import re
import sys
from pathlib import Path

PBX = Path(__file__).resolve().parent.parent / "ios" / "Runner.xcodeproj" / "project.pbxproj"

# Deterministic UUIDs (5AA prefix keeps them visually distinct from Xcode's).
U = {
    "appex":        "5AA0000000000000000000A1",
    "provider":     "5AA0000000000000000000A2",
    "bridge":       "5AA0000000000000000000A3",
    "miragebr":     "5AA0000000000000000000A4",
    "shared":       "5AA0000000000000000000A5",
    "extinfo":      "5AA0000000000000000000A6",
    "extentit":     "5AA0000000000000000000A7",
    "runnerent":    "5AA0000000000000000000A8",
    "mirage":       "5AA0000000000000000000A9",
    "netext":       "5AA0000000000000000000AA",
    "vpnplugin":    "5AA0000000000000000000AB",
    "grp_ext":      "5AA0000000000000000000B1",
    "grp_fw":       "5AA0000000000000000000B2",
    "grp_shared":   "5AA0000000000000000000B3",
    "tgt":          "5AA0000000000000000000C1",
    "ext_src":      "5AA0000000000000000000C2",
    "ext_fw":       "5AA0000000000000000000C3",
    "ext_res":      "5AA0000000000000000000C4",
    "embed_ext":    "5AA0000000000000000000C5",
    "proxy":        "5AA0000000000000000000C6",
    "dep":          "5AA0000000000000000000C7",
    "cfg_debug":    "5AA0000000000000000000D1",
    "cfg_rel":      "5AA0000000000000000000D2",
    "cfg_prof":     "5AA0000000000000000000D3",
    "cfg_list":     "5AA0000000000000000000D4",
    "bf_provider":  "5AA0000000000000000000E1",
    "bf_bridge":    "5AA0000000000000000000E2",
    "bf_miragebr":  "5AA0000000000000000000E3",
    "bf_shared_pt": "5AA0000000000000000000E4",
    "bf_mirage_pt": "5AA0000000000000000000E5",
    "bf_netext":    "5AA0000000000000000000E6",
    "bf_mirage_r":  "5AA0000000000000000000E7",
    "bf_mirage_e":  "5AA0000000000000000000E8",
    "bf_appex":     "5AA0000000000000000000E9",
    "bf_plugin":    "5AA0000000000000000000EA",
    "bf_shared_r":  "5AA0000000000000000000EB",
}

RUNNER_ID = "97C146ED1CF9000F007C117D"
MAIN_GROUP = "97C146E51CF9000F007C117D"
PRODUCTS_GROUP = "97C146EF1CF9000F007C117D"
RUNNER_GROUP = "97C146F01CF9000F007C117D"
RUNNER_SOURCES = "97C146EA1CF9000F007C117D"
RUNNER_FRAMEWORKS = "97C146EB1CF9000F007C117D"
EMBED_FRAMEWORKS = "9705A1C41CF9048500538489"
PROJECT_ID = "97C146E61CF9000F007C117D"


def insert_before_end(text: str, section: str, block: str) -> str:
    marker = f"/* End {section} section */"
    assert marker in text, f"missing section {section}"
    return text.replace(marker, block + marker)


def main() -> int:
    text = PBX.read_text()
    check_only = "--check" in sys.argv

    if "PacketTunnel" in text:
        if check_only:
            print("PacketTunnel target already present")
            return 0
        print("PacketTunnel already in project — refusing to double-apply", file=sys.stderr)
        return 1
    if check_only:
        print("PacketTunnel target missing")
        return 1

    # --- PBXBuildFile ---
    build_files = "".join(
        f"\t\t{u} /* {name} */ = {{isa = PBXBuildFile; fileRef = {ref} /* {name.split(' in ')[0]} */;{extra} }};\n"
        for u, ref, name, extra in [
            (U["bf_provider"], U["provider"], "PacketTunnelProvider.swift in Sources", ""),
            (U["bf_bridge"], U["bridge"], "TunSocksBridge.swift in Sources", ""),
            (U["bf_miragebr"], U["miragebr"], "MirageBridge.swift in Sources", ""),
            (U["bf_shared_pt"], U["shared"], "SharedTunnelState.swift in Sources", ""),
            (U["bf_mirage_pt"], U["mirage"], "Mirage.xcframework in Frameworks", ""),
            (U["bf_netext"], U["netext"], "NetworkExtension.framework in Frameworks", ""),
            (U["bf_mirage_r"], U["mirage"], "Mirage.xcframework in Frameworks", ""),
            (U["bf_mirage_e"], U["mirage"], "Mirage.xcframework in Embed Frameworks",
             " settings = {ATTRIBUTES = (CodeSignOnCopy, RemoveHeadersOnCopy, ); };"),
            (U["bf_appex"], U["appex"], "PacketTunnel.appex in Embed App Extensions",
             " settings = {ATTRIBUTES = (RemoveHeadersOnCopy, ); };"),
            (U["bf_plugin"], U["vpnplugin"], "VpnPlugin.swift in Sources", ""),
            (U["bf_shared_r"], U["shared"], "SharedTunnelState.swift in Sources", ""),
        ]
    )
    text = insert_before_end(text, "PBXBuildFile", build_files)

    # --- PBXContainerItemProxy ---
    text = insert_before_end(text, "PBXContainerItemProxy", f"""\
\t\t{U["proxy"]} /* PBXContainerItemProxy */ = {{
\t\t\tisa = PBXContainerItemProxy;
\t\t\tcontainerPortal = {PROJECT_ID} /* Project object */;
\t\t\tproxyType = 1;
\t\t\tremoteGlobalIDString = {U["tgt"]};
\t\t\tremoteInfo = PacketTunnel;
\t\t}};
""")

    # --- PBXCopyFilesBuildPhase (Embed App Extensions) ---
    text = insert_before_end(text, "PBXCopyFilesBuildPhase", f"""\
\t\t{U["embed_ext"]} /* Embed App Extensions */ = {{
\t\t\tisa = PBXCopyFilesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tdstPath = "";
\t\t\tdstSubfolderSpec = 13;
\t\t\tfiles = (
\t\t\t\t{U["bf_appex"]} /* PacketTunnel.appex in Embed App Extensions */,
\t\t\t);
\t\t\tname = "Embed App Extensions";
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
""")

    # --- PBXFileReference ---
    refs = f"""\
\t\t{U["appex"]} /* PacketTunnel.appex */ = {{isa = PBXFileReference; explicitFileType = "wrapper.app-extension"; includeInIndex = 0; path = PacketTunnel.appex; sourceTree = BUILT_PRODUCTS_DIR; }};
\t\t{U["provider"]} /* PacketTunnelProvider.swift */ = {{isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.swift; path = PacketTunnelProvider.swift; sourceTree = "<group>"; }};
\t\t{U["bridge"]} /* TunSocksBridge.swift */ = {{isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.swift; path = TunSocksBridge.swift; sourceTree = "<group>"; }};
\t\t{U["miragebr"]} /* MirageBridge.swift */ = {{isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.swift; path = MirageBridge.swift; sourceTree = "<group>"; }};
\t\t{U["shared"]} /* SharedTunnelState.swift */ = {{isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.swift; path = SharedTunnelState.swift; sourceTree = "<group>"; }};
\t\t{U["extinfo"]} /* Info.plist */ = {{isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = "<group>"; }};
\t\t{U["extentit"]} /* PacketTunnel.entitlements */ = {{isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = text.plist.entitlements; path = PacketTunnel.entitlements; sourceTree = "<group>"; }};
\t\t{U["runnerent"]} /* Runner.entitlements */ = {{isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = text.plist.entitlements; path = Runner.entitlements; sourceTree = "<group>"; }};
\t\t{U["vpnplugin"]} /* VpnPlugin.swift */ = {{isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.swift; path = VpnPlugin.swift; sourceTree = "<group>"; }};
\t\t{U["mirage"]} /* Mirage.xcframework */ = {{isa = PBXFileReference; lastKnownFileType = wrapper.xcframework; name = Mirage.xcframework; path = "../apple/Frameworks/Mirage.xcframework"; sourceTree = "<group>"; }};
\t\t{U["netext"]} /* NetworkExtension.framework */ = {{isa = PBXFileReference; lastKnownFileType = wrapper.framework; name = NetworkExtension.framework; path = Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/NetworkExtension.framework; sourceTree = DEVELOPER_DIR; }};
"""
    text = insert_before_end(text, "PBXFileReference", refs)

    # --- PBXFrameworksBuildPhase: extension phase + Runner Mirage link ---
    text = insert_before_end(text, "PBXFrameworksBuildPhase", f"""\
\t\t{U["ext_fw"]} /* Frameworks */ = {{
\t\t\tisa = PBXFrameworksBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t\t{U["bf_mirage_pt"]} /* Mirage.xcframework in Frameworks */,
\t\t\t\t{U["bf_netext"]} /* NetworkExtension.framework in Frameworks */,
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
""")
    runner_fw = f"{RUNNER_FRAMEWORKS} /* Frameworks */ = {{\n\t\t\tisa = PBXFrameworksBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t);"
    assert runner_fw in text
    text = text.replace(
        runner_fw,
        runner_fw.replace("files = (\n\t\t\t);",
                          f'files = (\n\t\t\t\t{U["bf_mirage_r"]} /* Mirage.xcframework in Frameworks */,\n\t\t\t);'),
    )
    # Runner Embed Frameworks: embed Mirage with CodeSignOnCopy.
    embed_fw = f"{EMBED_FRAMEWORKS} /* Embed Frameworks */ = {{\n\t\t\tisa = PBXCopyFilesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tdstPath = \"\";\n\t\t\tdstSubfolderSpec = 10;\n\t\t\tfiles = (\n\t\t\t);"
    assert embed_fw in text
    text = text.replace(
        embed_fw,
        embed_fw.replace("files = (\n\t\t\t);",
                         f'files = (\n\t\t\t\t{U["bf_mirage_e"]} /* Mirage.xcframework in Embed Frameworks */,\n\t\t\t);'),
    )

    # --- PBXGroup: PacketTunnel + Frameworks + Shared groups; patch children ---
    groups = f"""\
\t\t{U["grp_ext"]} /* PacketTunnel */ = {{
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
\t\t\t\t{U["provider"]} /* PacketTunnelProvider.swift */,
\t\t\t\t{U["bridge"]} /* TunSocksBridge.swift */,
\t\t\t\t{U["miragebr"]} /* MirageBridge.swift */,
\t\t\t\t{U["extinfo"]} /* Info.plist */,
\t\t\t\t{U["extentit"]} /* PacketTunnel.entitlements */,
\t\t\t);
\t\t\tpath = PacketTunnel;
\t\t\tsourceTree = "<group>";
\t\t}};
\t\t{U["grp_shared"]} /* Shared */ = {{
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
\t\t\t\t{U["shared"]} /* SharedTunnelState.swift */,
\t\t\t);
\t\t\tpath = Shared;
\t\t\tsourceTree = "<group>";
\t\t}};
\t\t{U["grp_fw"]} /* Frameworks */ = {{
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
\t\t\t\t{U["mirage"]} /* Mirage.xcframework */,
\t\t\t\t{U["netext"]} /* NetworkExtension.framework */,
\t\t\t);
\t\t\tname = Frameworks;
\t\t\tsourceTree = "<group>";
\t\t}};
"""
    text = insert_before_end(text, "PBXGroup", groups)

    # main group children += Frameworks, PacketTunnel, Shared (before Products)
    main_children_old = """\
		97C146E51CF9000F007C117D = {
			isa = PBXGroup;
			children = (
				9740EEB11CF90186004384FC /* Flutter */,
				97C146F01CF9000F007C117D /* Runner */,
				97C146EF1CF9000F007C117D /* Products */,
				331C8082294A63A400263BE5 /* RunnerTests */,
			);"""
    main_children_new = """\
		97C146E51CF9000F007C117D = {
			isa = PBXGroup;
			children = (
				9740EEB11CF90186004384FC /* Flutter */,
				97C146F01CF9000F007C117D /* Runner */,
				5AA0000000000000000000B3 /* Shared */,
				5AA0000000000000000000B1 /* PacketTunnel */,
				5AA0000000000000000000B2 /* Frameworks */,
				97C146EF1CF9000F007C117D /* Products */,
				331C8082294A63A400263BE5 /* RunnerTests */,
			);"""
    assert main_children_old in text
    text = text.replace(main_children_old, main_children_new)

    # Products group children += PacketTunnel.appex
    products_old = """\
		97C146EF1CF9000F007C117D /* Products */ = {
			isa = PBXGroup;
			children = (
				97C146EE1CF9000F007C117D /* Runner.app */,
				331C8081294A63A400263BE5 /* RunnerTests.xctest */,
			);"""
    products_new = """\
		97C146EF1CF9000F007C117D /* Products */ = {
			isa = PBXGroup;
			children = (
				97C146EE1CF9000F007C117D /* Runner.app */,
				331C8081294A63A400263BE5 /* RunnerTests.xctest */,
				5AA0000000000000000000A1 /* PacketTunnel.appex */,
			);"""
    assert products_old in text
    text = text.replace(products_old, products_new)

    # Runner group children += VpnPlugin.swift, Runner.entitlements
    runner_grp_old = """\
				74858FAE1ED2DC5600515810 /* AppDelegate.swift */,
				74858FAD1ED2DC5600515810 /* Runner-Bridging-Header.h */,
			);"""
    runner_grp_new = """\
				74858FAE1ED2DC5600515810 /* AppDelegate.swift */,
				5AA0000000000000000000AB /* VpnPlugin.swift */,
				74858FAD1ED2DC5600515810 /* Runner-Bridging-Header.h */,
				5AA0000000000000000000A8 /* Runner.entitlements */,
			);"""
    assert runner_grp_old in text
    text = text.replace(runner_grp_old, runner_grp_new)

    # --- PBXNativeTarget: PacketTunnel ---
    text = insert_before_end(text, "PBXNativeTarget", f"""\
\t\t{U["tgt"]} /* PacketTunnel */ = {{
\t\t\tisa = PBXNativeTarget;
\t\t\tbuildConfigurationList = {U["cfg_list"]} /* Build configuration list for PBXNativeTarget "PacketTunnel" */;
\t\t\tbuildPhases = (
\t\t\t\t{U["ext_src"]} /* Sources */,
\t\t\t\t{U["ext_fw"]} /* Frameworks */,
\t\t\t\t{U["ext_res"]} /* Resources */,
\t\t\t);
\t\t\tbuildRules = (
\t\t\t);
\t\t\tdependencies = (
\t\t\t);
\t\t\tname = PacketTunnel;
\t\t\tproductName = PacketTunnel;
\t\t\tproductReference = {U["appex"]} /* PacketTunnel.appex */;
\t\t\tproductType = "com.apple.product-type.app-extension";
\t\t}};
""")

    # Runner target: dependencies += PacketTunnel dep; buildPhases += Embed App Extensions
    runner_tgt_old = """\
			dependencies = (
			);
			name = Runner;"""
    runner_tgt_new = f"""\
			dependencies = (
				{U["dep"]} /* PBXTargetDependency */,
			);
			name = Runner;"""
    assert runner_tgt_old in text
    text = text.replace(runner_tgt_old, runner_tgt_new)

    embed_line = "\t\t\t\t9705A1C41CF9048500538489 /* Embed Frameworks */,\n"
    assert embed_line in text
    text = text.replace(embed_line, embed_line + f"\t\t\t\t{U['embed_ext']} /* Embed App Extensions */,\n")

    # --- PBXProject: targets += PacketTunnel; TargetAttributes += ext ---
    targets_old = """\
			targets = (
				97C146ED1CF9000F007C117D /* Runner */,
				331C8080294A63A400263BE5 /* RunnerTests */,
			);"""
    targets_new = f"""\
			targets = (
				97C146ED1CF9000F007C117D /* Runner */,
				{U["tgt"]} /* PacketTunnel */,
				331C8080294A63A400263BE5 /* RunnerTests */,
			);"""
    assert targets_old in text
    text = text.replace(targets_old, targets_new)

    # Insert a TargetAttributes entry for the new target right after the
    # Runner entry (anchored on its unique LastSwiftMigration marker).
    m = re.search(r"(LastSwiftMigration = 1100;\s*\};)", text)
    assert m, "TargetAttributes Runner entry not found"
    text = text[:m.end(1)] + f"""
\t\t\t\t\t{U["tgt"]} = {{
\t\t\t\t\t\tCreatedOnToolsVersion = 16.0;
\t\t\t\t\t}};""" + text[m.end(1):]

    # --- PBXResourcesBuildPhase: ext ---
    text = insert_before_end(text, "PBXResourcesBuildPhase", f"""\
\t\t{U["ext_res"]} /* Resources */ = {{
\t\t\tisa = PBXResourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
""")

    # --- PBXSourcesBuildPhase: ext phase + Runner sources additions ---
    text = insert_before_end(text, "PBXSourcesBuildPhase", f"""\
\t\t{U["ext_src"]} /* Sources */ = {{
\t\t\tisa = PBXSourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t\t{U["bf_provider"]} /* PacketTunnelProvider.swift in Sources */,
\t\t\t\t{U["bf_bridge"]} /* TunSocksBridge.swift in Sources */,
\t\t\t\t{U["bf_miragebr"]} /* MirageBridge.swift in Sources */,
\t\t\t\t{U["bf_shared_pt"]} /* SharedTunnelState.swift in Sources */,
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
""")
    runner_src_old = """\
				74858FAF1ED2DC5600515810 /* AppDelegate.swift in Sources */,
				1498D2341E8E89220040F4C2 /* GeneratedPluginRegistrant.m in Sources */,
			);"""
    runner_src_new = f"""\
				74858FAF1ED2DC5600515810 /* AppDelegate.swift in Sources */,
				{U["bf_plugin"]} /* VpnPlugin.swift in Sources */,
				{U["bf_shared_r"]} /* SharedTunnelState.swift in Sources */,
				1498D2341E8E89220040F4C2 /* GeneratedPluginRegistrant.m in Sources */,
			);"""
    assert runner_src_old in text
    text = text.replace(runner_src_old, runner_src_new)

    # --- PBXTargetDependency ---
    text = insert_before_end(text, "PBXTargetDependency", f"""\
\t\t{U["dep"]} /* PBXTargetDependency */ = {{
\t\t\tisa = PBXTargetDependency;
\t\t\ttarget = {U["tgt"]} /* PacketTunnel */;
\t\t\ttargetProxy = {U["proxy"]} /* PBXContainerItemProxy */;
\t\t}};
""")

    # --- XCBuildConfiguration: extension Debug/Release/Profile ---
    def ext_cfg(name: str, extra: str = "") -> str:
        opt = "SWIFT_OPTIMIZATION_LEVEL = \"-Onone\";\n\t\t\t\tSWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;" if name == "Debug" else ""
        return f"""\
\t\t{U[{"Debug": "cfg_debug", "Release": "cfg_rel", "Profile": "cfg_prof"}[name]]} /* {name} */ = {{
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
\t\t\t\tCLANG_ENABLE_MODULES = YES;
\t\t\t\tCODE_SIGN_ENTITLEMENTS = PacketTunnel/PacketTunnel.entitlements;
\t\t\t\tCODE_SIGN_STYLE = Automatic;
\t\t\t\tCURRENT_PROJECT_VERSION = 1;
\t\t\t\tGENERATE_INFOPLIST_FILE = NO;
\t\t\t\tINFOPLIST_FILE = PacketTunnel/Info.plist;
\t\t\t\tIPHONEOS_DEPLOYMENT_TARGET = 13.0;
\t\t\t\tLD_RUNPATH_SEARCH_PATHS = (
\t\t\t\t\t"$(inherited)",
\t\t\t\t\t"@executable_path/Frameworks",
\t\t\t\t\t"@executable_path/../../Frameworks",
\t\t\t\t);
\t\t\t\tMARKETING_VERSION = 1.0;
\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = homes.milky.vpn.PacketTunnel;
\t\t\t\tPRODUCT_NAME = "$(TARGET_NAME)";
\t\t\t\tSKIP_INSTALL = YES;
\t\t\t\tSWIFT_EMIT_LOC_STRINGS = YES;
\t\t\t\tSWIFT_VERSION = 5.0;
\t\t\t\tTARGETED_DEVICE_FAMILY = "1,2";
\t\t\t\tFRAMEWORK_SEARCH_PATHS = (
\t\t\t\t\t"$(inherited)",
\t\t\t\t\t"$(SRCROOT)/../apple/Frameworks",
\t\t\t\t);
\t\t\t\t{opt}
\t\t\t}};
\t\t\tname = {name};
\t\t}};
"""
    ext_cfgs = ext_cfg("Debug") + ext_cfg("Release") + ext_cfg("Profile")
    text = insert_before_end(text, "XCBuildConfiguration", ext_cfgs)

    # Runner configs: bundle id + entitlements + framework search paths
    bid_old = "PRODUCT_BUNDLE_IDENTIFIER = homes.milky.milkyvpn;"
    count = text.count(bid_old)
    assert count == 3, f"expected 3 Runner bundle-id settings, found {count}"
    text = text.replace(
        bid_old,
        """PRODUCT_BUNDLE_IDENTIFIER = homes.milky.vpn;
				CODE_SIGN_ENTITLEMENTS = Runner/Runner.entitlements;
				FRAMEWORK_SEARCH_PATHS = (
					"$(inherited)",
					"$(SRCROOT)/../apple/Frameworks",
				);""",
    )

    # --- XCConfigurationList: ext ---
    text = insert_before_end(text, "XCConfigurationList", f"""\
\t\t{U["cfg_list"]} /* Build configuration list for PBXNativeTarget "PacketTunnel" */ = {{
\t\t\tisa = XCConfigurationList;
\t\t\tbuildConfigurations = (
\t\t\t\t{U["cfg_debug"]} /* Debug */,
\t\t\t\t{U["cfg_rel"]} /* Release */,
\t\t\t\t{U["cfg_prof"]} /* Profile */,
\t\t\t);
\t\t\tdefaultConfigurationIsVisible = 0;
\t\t\tdefaultConfigurationName = Release;
\t\t}};
""")

    PBX.write_text(text)
    print("PacketTunnel target injected into ios/Runner.xcodeproj")
    return 0


if __name__ == "__main__":
    sys.exit(main())
