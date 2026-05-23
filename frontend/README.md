# Stegcore Frontend

React + TypeScript + Vite frontend for the Stegcore desktop application.

## Setup

```bash
npm install
```

## Development

Run alongside `cargo tauri dev` from the workspace root:

```bash
npm run dev    # Vite dev server on :1420
```

## Type checking

```bash
npx tsc --noEmit
```

## Architecture

- **Routes:** Home, Embed (4-step wizard), Extract (3-step), Analyse, Learn
- **Components:** DropZone, ScoreCard, EntropyBar, Toggle, Settings,
  Installer, ToastContainer, KeyboardShortcuts, AnalysisDetail,
  ProcessingScreen, SuccessCheck, StepTrack, IconButton
- **Steganalysis charts:** Chi-Squared, RS Analysis, SPA Gauge,
  LSB Heatmap, Audio Oscilloscope (all canvas-based with
  `requestAnimationFrame` loops)
- **State:** Zustand stores (embedStore, extractStore, settingsStore, dragStore)
- **IPC:** Typed wrappers in `lib/ipc.ts` calling Tauri `invoke()`
- **Design tokens:** `--sc-*` / `--ui-*` CSS custom properties
- **Animations:** CSS transitions + canvas chart animations. Respect
  `reduce-motion` setting.

## Key conventions

- Inline styles using design token variables (no hardcoded hex)
- CSS classes for hover states (no `onMouseEnter` style mutations)
- `React.memo()` on heavy sub-components
- Lazy route loading via `React.lazy()` + `Suspense`
- `createPortal` for overlays that escape overflow containers
- Icons from lucide-react exclusively
- System font stack; no external font loading
- British English in all user-facing strings
