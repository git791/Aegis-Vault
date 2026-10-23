# Design System: "Vault Glass"

**Style:** dark, glassmorphic security console. Calm, precise, trustworthy; subtle depth, no gimmicks.

## Colour palette
| Role | Hex | Use |
|---|---|---|
| Background | `#0B1020` | App canvas |
| Surface | `#121A2E` | Cards, panels (with 60-70% opacity + blur for glass) |
| Border | `#2A3553` | Dividers; use stronger border token on controls |
| Text | `#E6EAF5` | Body |
| Muted text | `#9AA6C4` | Secondary |
| Accent cyan | `#22D3EE` | Primary actions, focus ring |
| Accent violet | `#8B5CF6` | X-Ray highlights, secondary accent |
| Success | `#34D399` | Verified / decrypted |
| Danger | `#F87171` | Tamper / wrong password |
| Warning | `#FBBF24` | Weak password |

Check every text/background pair for WCAG AA (4.5:1 body, 3:1 large text and UI borders) with a contrast tool before shipping.

## Typography
- **UI / body:** Inter
- **Headings:** Space Grotesk
- **Hex, bytes, keys:** JetBrains Mono (tabular, clear 0/O)
All from Google Fonts or self-hosted; system-font fallbacks included.

## Layout
Five-tab single page: Vault, Inspector, Password Lab, Avalanche Lab, Keys, plus X-Ray. 8px spacing grid, 12px corner radius, max content width ~1100px, responsive down to mobile.

## Components
Drop zone with progress ring, segmented controls, byte-grid (4x4 cells, changed bytes glow violet), bit-picker for Avalanche Lab, strength meter, status toasts.

## Motion and accessibility
Short 150-250ms transitions; honour `prefers-reduced-motion`. Keyboard-reachable controls, visible focus ring, never rely on colour alone (icons + text for success/fail), ARIA labels on visualizations.
