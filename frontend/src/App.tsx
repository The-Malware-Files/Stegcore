// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import React, { useState, useCallback, useEffect, useRef, createContext, useContext } from 'react'
import { BrowserRouter, Routes, Route, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Sun, Moon, Cog, ArrowLeft, ArrowRight, HelpCircle } from 'lucide-react'
import SplashDark from './components/SplashDark'
import SplashLight from './components/SplashLight'
import { Settings as SettingsPanel } from './components/Settings'
import { StepTrack } from './components/StepTrack'
import { IconButton } from './components/IconButton'
import { effectiveTheme, toggleTheme } from './lib/theme'
import { useSettingsStore, FONT_SIZE_PX } from './lib/stores/settingsStore'
import Home from './routes/Home'
const Embed = React.lazy(() => import('./routes/Embed'))
const Extract = React.lazy(() => import('./routes/Extract'))
const Analyse = React.lazy(() => import('./routes/Analyse'))
const Learn = React.lazy(() => import('./routes/Learn'))
import { Installer } from './components/Installer'
import { ToastContainer } from './components/ToastContainer'
import { KeyboardShortcuts } from './components/KeyboardShortcuts'

// ── Theme observation ─────────────────────────────────────────────────────

const initialTheme = effectiveTheme()

// ── Footer context — wizard routes provide back/continue actions ──────────

export interface FooterConfig {
  backLabel?: string
  backAction?: (() => void) | null
  continueLabel?: string
  continueAction?: (() => void) | null
  continueDisabled?: boolean
  steps?: string[]
  currentStep?: number
}

const FooterCtx = createContext<(cfg: FooterConfig | null) => void>(() => undefined)
export function useFooter(cfg: FooterConfig | null) {
  const set = useContext(FooterCtx)
  useEffect(() => {
    set(cfg)
    return () => set(null)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cfg?.backLabel, cfg?.continueLabel, cfg?.continueDisabled, cfg?.currentStep, !!cfg?.backAction, !!cfg?.continueAction])
}

// ── Error boundary — prevents blank screens on render crashes ─────────────

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          justifyContent: 'center', height: '100%', gap: 12, padding: 32,
          color: 'var(--ui-text)', textAlign: 'center',
        }}>
          <p style={{ fontSize: 15, fontWeight: 600 }}>Something went wrong</p>
          <p style={{ fontSize: 12, color: 'var(--ui-text2)', maxWidth: 400 }}>
            {this.state.error.message}
          </p>
          <button
            onClick={() => { this.setState({ error: null }); window.history.back() }}
            style={{
              marginTop: 8, padding: '8px 20px', borderRadius: 7,
              background: 'var(--ui-accent)', color: '#fff', border: 'none',
              fontSize: 12, fontWeight: 500, cursor: 'pointer',
            }}
          >
            Go back
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// ── Verse bar — rotating NLT Bible verse in footer ──────────────────────

function VerseBar() {
  const { settings } = useSettingsStore()
  const [verse, setVerse] = useState<{ text: string; reference: string } | null>(null)
  const outerRef = useRef<HTMLDivElement>(null)
  const innerRef = useRef<HTMLSpanElement>(null)
  const [scrolling, setScrolling] = useState(false)
  const [overflow, setOverflow] = useState(0) // pixels of overflow
  const idleTimer = useRef<ReturnType<typeof setTimeout>>(undefined)
  const scrollPhase = useRef<'idle' | 'scrollLeft' | 'pauseLeft' | 'scrollBack'>('idle')
  const scrollPos = useRef(0)
  const rafId = useRef(0)

  useEffect(() => {
    if (!settings.bibleVerses) { setVerse(null); return }
    let cancelled = false

    const fetchVerse = () => {
      import('./lib/ipc').then(({ getVerse }) => getVerse()).then(v => {
        if (!cancelled) setVerse(v)
      }).catch(() => {})
    }

    fetchVerse()
    const interval = setInterval(fetchVerse, 600_000) // 10 minutes
    return () => { cancelled = true; clearInterval(interval) }
  }, [settings.bibleVerses])

  // Measure overflow
  useEffect(() => {
    if (!innerRef.current || !outerRef.current) return
    const measure = () => {
      const inner = innerRef.current!.scrollWidth
      const outer = outerRef.current!.clientWidth
      setOverflow(Math.max(0, inner - outer))
    }
    measure()
    const obs = new ResizeObserver(measure)
    obs.observe(outerRef.current)
    return () => obs.disconnect()
  }, [verse])

  // Idle detection — start scrolling after 5s of no mouse activity
  useEffect(() => {
    if (overflow <= 0) return

    const resetIdle = () => {
      // User moved — snap back quickly
      if (scrolling) {
        setScrolling(false)
        scrollPhase.current = 'idle'
        cancelAnimationFrame(rafId.current)
        // Animate back to 0
        const el = innerRef.current
        if (el) {
          el.style.transition = 'transform 0.4s ease-out'
          el.style.transform = 'translateX(0)'
          setTimeout(() => { if (el) el.style.transition = '' }, 400)
        }
        scrollPos.current = 0
      }
      clearTimeout(idleTimer.current)
      idleTimer.current = setTimeout(() => setScrolling(true), 5000)
    }

    resetIdle() // start the first idle timer

    window.addEventListener('mousemove', resetIdle)
    window.addEventListener('keydown', resetIdle)
    window.addEventListener('click', resetIdle)
    return () => {
      window.removeEventListener('mousemove', resetIdle)
      window.removeEventListener('keydown', resetIdle)
      window.removeEventListener('click', resetIdle)
      clearTimeout(idleTimer.current)
      cancelAnimationFrame(rafId.current)
    }
  }, [overflow, scrolling])

  // Animation loop when scrolling
  const restartTimer = useRef<number>(0)

  useEffect(() => {
    if (!scrolling || overflow <= 0) return
    const el = innerRef.current
    if (!el) return

    el.style.transition = ''
    scrollPhase.current = 'scrollLeft'
    scrollPos.current = 0
    let pauseStart = 0
    const SPEED = 0.4 // px per frame (~24px/s at 60fps)

    const tick = () => {
      switch (scrollPhase.current) {
        case 'scrollLeft':
          scrollPos.current = Math.min(scrollPos.current + SPEED, overflow)
          el.style.transform = `translateX(-${scrollPos.current}px)`
          if (scrollPos.current >= overflow) {
            scrollPhase.current = 'pauseLeft'
            pauseStart = performance.now()
          }
          break
        case 'pauseLeft':
          if (performance.now() - pauseStart > 5000) {
            scrollPhase.current = 'scrollBack'
          }
          break
        case 'scrollBack':
          scrollPos.current = Math.max(scrollPos.current - SPEED, 0)
          el.style.transform = `translateX(-${scrollPos.current}px)`
          if (scrollPos.current <= 0) {
            scrollPhase.current = 'idle'
            // Pause, then restart
            restartTimer.current = window.setTimeout(() => {
              if (scrolling) scrollPhase.current = 'scrollLeft'
            }, 5000)
          }
          break
        case 'idle':
          break
      }
      if (scrolling) rafId.current = requestAnimationFrame(tick)
    }

    rafId.current = requestAnimationFrame(tick)
    return () => {
      cancelAnimationFrame(rafId.current)
      clearTimeout(restartTimer.current)
    }
  }, [scrolling, overflow])

  if (!verse) return <div style={{ flex: 1 }} />

  return (
    <div
      ref={outerRef}
      style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        overflow: 'hidden',
        padding: '0 12px',
        minWidth: 0,
      }}
    >
      <div style={{ flex: 1, overflow: 'hidden', minWidth: 0 }}>
        <span
          ref={innerRef}
          style={{
            display: 'block',
            fontSize: 'var(--font-size-xs)',
            fontStyle: 'italic',
            color: 'var(--ui-text2)',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: scrolling ? 'clip' : 'ellipsis',
            willChange: scrolling ? 'transform' : undefined,
          }}
        >
          {verse.text}
        </span>
      </div>
      <span style={{
        fontSize: 'var(--font-size-xs)',
        color: 'var(--ui-text2)',
        whiteSpace: 'nowrap',
        flexShrink: 0,
        fontFamily: "'Space Mono', monospace",
        opacity: 0.7,
      }}>
        — {verse.reference}
      </span>
    </div>
  )
}

// ── Layout ────────────────────────────────────────────────────────────────

function Layout({
  settingsOpen,
  setSettingsOpen,
  setShortcutsOpen,
}: {
  settingsOpen: boolean
  setSettingsOpen: (v: boolean) => void
  setShortcutsOpen: (v: boolean) => void
}) {
  const location = useLocation()
  const navigate = useNavigate()
  const [footerCfg, setFooterCfg] = useState<FooterConfig | null>(null)
  const [theme, setThemeState] = useState<'dark' | 'light'>(effectiveTheme())
  const isHome = location.pathname === '/'
  const prevPathRef = useRef(location.pathname)
  const isBack = location.pathname === '/' || (prevPathRef.current !== '/' && location.pathname < prevPathRef.current)
  useEffect(() => { prevPathRef.current = location.pathname }, [location.pathname])

  // Keep local theme state in sync with OS changes AND settings panel changes
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const mqHandler = () => setThemeState(effectiveTheme())
    mq.addEventListener('change', mqHandler)

    // Watch for data-theme attribute changes (triggered by settings panel)
    const obs = new MutationObserver(() => setThemeState(effectiveTheme()))
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })

    return () => {
      mq.removeEventListener('change', mqHandler)
      obs.disconnect()
    }
  }, [])

  const handleThemeToggle = useCallback(() => {
    toggleTheme()
    setThemeState(effectiveTheme())
  }, [])

  return (
    <FooterCtx.Provider value={setFooterCfg}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

        {/* ── Header ── */}
        <header style={{
          flexShrink: 0,
          height: 56,
          display: 'flex',
          alignItems: 'center',
          padding: '0 1.25rem',
          borderBottom: '1px solid var(--ui-border)',
          background: 'var(--ui-surface)',
          gap: '0.75rem',
        }}>
          {/* Logo + wordmark */}
          <button
            onClick={() => navigate('/')}
            aria-label="Stegcore home"
            style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'transparent', border: 'none', cursor: 'pointer', padding: 0 }}
          >
            {/* Layered Stack SVG */}
            <svg width="28" height="28" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
              <rect x="8"  y="10" width="48" height="12" rx="2.5" fill="#4da6ff" />
              <rect x="8"  y="28" width="21" height="12" rx="2.5" fill="#2a7fff" />
              <rect x="35" y="28" width="21" height="12" rx="2.5" fill="#2a7fff" />
              <rect x="8"  y="46" width="48" height="12" rx="2.5" fill="#1252cc" />
            </svg>
            <span style={{ fontWeight: 500, fontSize: 14, letterSpacing: '0.15em', color: 'var(--ui-text)', textTransform: 'uppercase' }}>
              STEGCORE
            </span>
          </button>

          {/* Spacer — step track on wizard routes, empty spacer otherwise */}
          <div style={{ flex: 1, display: 'flex', justifyContent: 'center' }}>
            {!isHome && footerCfg?.steps && footerCfg.currentStep !== undefined && (
              <StepTrack steps={footerCfg.steps} current={footerCfg.currentStep} />
            )}
          </div>

          {/* Icon buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <IconButton
              icon={HelpCircle}
              label="Keyboard shortcuts"
              onClick={() => setShortcutsOpen(true)}
            />
            <IconButton
              icon={theme === 'dark' ? Sun : Moon}
              label="Toggle theme"
              onClick={handleThemeToggle}
            />
            <IconButton
              icon={Cog}
              label="Settings"
              onClick={() => setSettingsOpen(true)}
              active={settingsOpen}
            />
          </div>
        </header>

        {/* ── Content ── */}
        <main style={{ flex: 1, overflow: 'hidden auto', background: 'var(--ui-bg)', position: 'relative' }}>
          <ErrorBoundary key={location.pathname}>
            <React.Suspense fallback={
              <div style={{ padding: '2.5rem 2rem', display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div className="sc-skeleton" style={{ width: 120, height: 14 }} />
                <div className="sc-skeleton" style={{ width: 260, height: 28 }} />
                <div className="sc-skeleton" style={{ width: 180, height: 12 }} />
                <div className="sc-skeleton" style={{ width: '100%', height: 160, marginTop: 8 }} />
              </div>
            }>
              <div className={isBack ? 'sc-enter-back' : 'sc-enter'} style={{ height: '100%' }}>
                <Outlet />
              </div>
            </React.Suspense>
          </ErrorBoundary>
        </main>

        {/* ── Footer nav — always present to prevent layout shift ── */}
        {/* Footer — always in DOM (prevents layout shift) */}
        {(() => {
          const showButtons = !isHome && (footerCfg?.backAction !== undefined || footerCfg?.continueAction !== undefined)
          return (
          <footer style={{
            flexShrink: 0,
            height: 52,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 1.5rem',
            borderTop: '1px solid var(--ui-border)',
            background: 'var(--ui-surface)',
          }}>
              <button
                onClick={footerCfg?.backAction ?? undefined}
                disabled={!footerCfg?.backAction}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  background: 'transparent',
                  border: '1px solid var(--ui-border)',
                  borderRadius: 'var(--sc-radius-btn)',
                  cursor: footerCfg?.backAction ? 'pointer' : 'default',
                  color: footerCfg?.backAction ? 'var(--ui-text)' : 'var(--ui-text2)',
                  fontSize: 13,
                  fontWeight: 500,
                  padding: '7px 16px',
                  opacity: showButtons ? (footerCfg?.backAction ? 1 : 0.4) : 0,
                  transition: 'opacity var(--sc-t-fast)',
                  pointerEvents: showButtons ? 'auto' : 'none',
                  flexShrink: 0,
                }}
              >
                <ArrowLeft size={14} />
                {footerCfg?.backLabel ?? 'Back'}
              </button>

              {/* Verse — fills the middle between the buttons */}
              <VerseBar />

              <button
                className="sc-btn-primary"
                onClick={footerCfg?.continueAction ?? undefined}
                disabled={!footerCfg?.continueAction || footerCfg?.continueDisabled}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  background: 'var(--ui-accent)',
                  border: 'none',
                  borderRadius: 'var(--sc-radius-btn)',
                  cursor: footerCfg?.continueAction && !footerCfg?.continueDisabled ? 'pointer' : 'default',
                  color: '#ffffff',
                  fontSize: 14,
                  fontWeight: 500,
                  padding: '9px 22px',
                  opacity: showButtons ? (footerCfg?.continueAction && !footerCfg?.continueDisabled ? 1 : 0.4) : 0,
                  transition: 'opacity var(--sc-t-fast)',
                  pointerEvents: showButtons ? 'auto' : 'none',
                  flexShrink: 0,
                }}
              >
                {footerCfg?.continueLabel ?? 'Continue'}
                <ArrowRight size={14} />
              </button>
          </footer>
          )
        })()}
      </div>
    </FooterCtx.Provider>
  )
}

// ── App root ──────────────────────────────────────────────────────────────

function App() {
  const [firstRun, setFirstRun] = useState<boolean | null>(null) // null = checking
  const [splashDone, setSplashDone] = useState(false)
  const [splashVisible, setSplashVisible] = useState(true)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)

  // Global `?` key opens keyboard shortcuts overlay
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA') return
      if (e.key === '?' && !settingsOpen) {
        e.preventDefault()
        setShortcutsOpen(v => !v)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [settingsOpen])

  const { load, settings } = useSettingsStore()

  useEffect(() => { load() }, [load])

  // Sync reduce-motion attribute with setting
  useEffect(() => {
    document.documentElement.setAttribute('data-reduce-motion', String(settings.reduceMotion))
  }, [settings.reduceMotion])

  // Sync interface size — zoom scales all inline px values proportionally
  useEffect(() => {
    const px = FONT_SIZE_PX[settings.fontSize] ?? 14
    const zoom = px / 14 // 14px is the base (zoom 1.0)
    document.documentElement.style.setProperty('--font-size-base', `${px}px`)
    document.documentElement.style.setProperty('--sc-ui-zoom', String(zoom))
  }, [settings.fontSize])

  // Check first-run status on mount
  useEffect(() => {
    import('@tauri-apps/api/core').then(({ invoke }) => {
      invoke<boolean>('is_first_run').then(setFirstRun)
    }).catch(() => {
      // Browser dev mode — skip installer
      setFirstRun(false)
    })
  }, [])

  const handleInstallerComplete = useCallback((prefs: { theme: string; defaultCipher: string }) => {
    // Apply preferences immediately
    const doc = document.documentElement
    if (prefs.theme === 'light') doc.setAttribute('data-theme', 'light')
    else if (prefs.theme === 'dark') doc.setAttribute('data-theme', 'dark')
    setFirstRun(false)
  }, [])

  const handleSplashComplete = useCallback(() => {
    setSplashDone(true)
    setTimeout(() => setSplashVisible(false), 200)
  }, [])

  // Still checking first-run status
  if (firstRun === null) return null

  // First-run: show installer instead of main app
  if (firstRun) return <Installer onComplete={handleInstallerComplete} />

  return (
    <>
      {splashVisible && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            opacity: splashDone ? 0 : 1,
            transition: splashDone ? 'opacity 200ms ease' : undefined,
            pointerEvents: splashDone ? 'none' : undefined,
          }}
        >
          {initialTheme === 'dark'
            ? <SplashDark onComplete={handleSplashComplete} />
            : <SplashLight onComplete={handleSplashComplete} />
          }
        </div>
      )}

      <BrowserRouter>
        <Routes>
          <Route element={<Layout settingsOpen={settingsOpen} setSettingsOpen={setSettingsOpen} setShortcutsOpen={setShortcutsOpen} />}>
            <Route index element={<Home />} />
            <Route path="embed"   element={<Embed />} />
            <Route path="extract" element={<Extract />} />
            <Route path="analyse" element={<Analyse />} />
            <Route path="learn"   element={<Learn />} />
          </Route>
        </Routes>
      </BrowserRouter>

      <SettingsPanel isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} />
      <ToastContainer />
      <KeyboardShortcuts open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
    </>
  )
}

export default App
