// Package v21ref is a frozen, byte-for-byte copy of the KAL/2 v2.1 session
// implementation as it shipped on main at commit 48f8a76 (release line
// v1.2.x). It exists for one purpose: tests of the current implementation
// talk to it as a wire-compatibility oracle, so a change to the session layer
// can be proven to interoperate with peers that are already deployed.
//
// DO NOT MODIFY — including to fix the defects the current implementation
// repairs. Deployed peers have those defects; the interop tests must see them.
// Nothing outside *_test.go files imports this package, so it is never linked
// into a release binary.
package v21ref
