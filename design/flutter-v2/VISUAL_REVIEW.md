# Milky Orb 2.0 — review of the real Flutter application

Reviewed 2026-09-05. These images are Flutter rasterizations of `MilkyApp`, its actual screens and shared components. The native bridge, subscription payload and device metadata are synthetic test fixtures. They do **not** demonstrate a working Android tunnel or an on-device screenshot.

The bundled Manrope and Material icon fonts are loaded by `test/support/harness.dart`. Subscription timestamps are frozen for repeatable baselines. Goldens run in the ordinary `flutter test`; the explicit icon export test runs separately.

## Review decisions

The initial concentric dark discs were rejected: they resembled a generic connection utility. The revised orb is a pale liquid body with broad curved milk folds, the M/drop mark, an animated outside arc while connecting, and cyan light with a small check after native verification. The mark remains recognizable in every state.

Specular card edges and stacked translucent surfaces were removed from Settings and Subscription. These screens use calm opaque surfaces. The selected country now fills a real tap target instead of a narrow text-height strip. The subscription dashboard is confined to its tab. Copy-link remains collapsed under Advanced.

Side-by-side review caught two defects missed by basic widget-existence assertions: the onboarding footer consumed the viewport on step three, and a missing diagnostic font rendered as Ahem blocks. Both were rejected and corrected; a new onboarding test asserts that each page heading is actually hit-testable. Diagnostics now uses the bundled family with readable tabular figures.

320dp phones use a smaller orb and a stacked flag/label selector, with scrolling for content that cannot fit. At enlarged text sizes buttons expand and the theme selector stacks. Tablets center a bounded interaction surface; individual controls retain phone-scale widths.

## Captures

| Requirement | Actual Flutter image |
|---|---|
| Onboarding 1 | `onboarding_1.png` |
| Onboarding privacy diagram | `onboarding_2.png` |
| Onboarding subscription | `onboarding_3.png` |
| Disconnected / dark | `home_disconnected_dark.png` |
| Connecting Finland | `home_connecting_finland.png` |
| Connected Finland | `home_connected_finland.png` |
| Connected USA | `home_connected_usa.png` |
| Auto connecting | `home_connecting.png` |
| Subscription | `subscription.png` |
| Settings | `settings.png` |
| Diagnostics | `diagnostics.png` |
| Diagnostic details sheet | `diagnostics_details.png` |
| Connection error sheet | `failure_sheet.png` |
| Light theme | `home_disconnected_light.png` |
| Tablet portrait | `home_tablet.png` |
| Tablet landscape | `tablet_landscape.png` |
| Import success | `import_success.png` |
| Removal confirmation | `remove_subscription.png` |
| Small phone | `home_small.png` |
| Large phone | `home_large.png` |

Four contact sheets (`review-board-1.png` through `review-board-4.png`) were reviewed side by side. Regenerate them on Windows with `tool/render_review_boards.ps1` after recording Flutter goldens. The older `design/screens` and HTML/SVG preview are historical materials, not evidence for this release.

## Practical limits

The app uses real Android system overlays and safe areas. Flutter test captures have no real Android status bar, so no artificial time, battery or signal indicator has been drawn. Validate system-bar contrast on a physical API 36 device.

Ambient rendering uses bounded vector drawing, isolated repaint boundaries and lifecycle/reduced-motion controls. Smooth 60fps is a target; no physical-device GPU/frame-time measurement is claimed.
