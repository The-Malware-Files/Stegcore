// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useRef, useState, useCallback } from 'react'
import { UploadCloud, X } from 'lucide-react'

interface DropZoneProps {
  accept: string[]           // e.g. ['.png', '.jpg']
  onFiles: (files: File[]) => void
  multiple?: boolean
  label?: string
  sublabel?: string
  preview?: string           // URL for image thumbnail
  fileName?: string          // shows file badge when set
  onRemove?: () => void
  error?: string
  disabled?: boolean
  className?: string
  /** Maximum file size in bytes. Files exceeding this are rejected. */
  maxBytes?: number
}

function extOf(file: File): string {
  return '.' + (file.name.split('.').pop() ?? '').toLowerCase()
}

export function DropZone({
  accept,
  onFiles,
  multiple = false,
  label = 'Drop a file here',
  sublabel,
  preview,
  fileName,
  onRemove,
  error,
  disabled = false,
  className = '',
  maxBytes,
}: DropZoneProps) {
  const [hovering, setHovering] = useState(false)
  const [rejected, setRejected] = useState(false)
  const [rejectMsg, setRejectMsg] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const validate = useCallback((files: File[]): File[] => {
    const valid = files.filter((f) => {
      if (!accept.includes(extOf(f))) return false
      if (maxBytes && f.size > maxBytes) {
        const sizeMB = Math.round(f.size / (1024 * 1024))
        const maxMB = Math.round(maxBytes / (1024 * 1024))
        setRejectMsg(`${f.name} is too large (${sizeMB} MB). Maximum: ${maxMB} MB`)
        setRejected(true)
        setTimeout(() => setRejected(false), 3000)
        return false
      }
      return true
    })
    return valid
  }, [accept, maxBytes])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setHovering(false)
    if (disabled) return

    const dropped = Array.from(e.dataTransfer.files)
    const valid = validate(dropped)

    if (valid.length === 0) {
      const exts = accept.join(', ')
      setRejectMsg(`Only ${exts} files supported`)
      setRejected(true)
      setTimeout(() => setRejected(false), 1500)
      return
    }

    onFiles(multiple ? valid : [valid[0]])
  }, [accept, disabled, multiple, onFiles, validate])

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? [])
    const valid = validate(files)
    if (valid.length > 0) onFiles(multiple ? valid : [valid[0]])
    // reset so the same file can be re-selected
    e.target.value = ''
  }, [multiple, onFiles, validate])

  const borderColor = error || rejected
    ? 'var(--ui-danger)'
    : hovering
      ? 'var(--ui-accent)'
      : 'var(--ui-border)'

  const bgColor = hovering
    ? 'color-mix(in srgb, var(--ui-accent) 5%, transparent)'
    : 'transparent'

  return (
    <div
      className={className}
      onDragOver={(e) => { e.preventDefault(); if (!disabled) setHovering(true) }}
      onDragLeave={() => setHovering(false)}
      onDrop={handleDrop}
      onClick={() => !disabled && inputRef.current?.click()}
      style={{
        border: `2px dashed ${borderColor}`,
        borderRadius: 'var(--sc-radius-card)',
        background: bgColor,
        padding: '2.5rem 1.5rem',
        textAlign: 'center',
        cursor: disabled ? 'default' : 'pointer',
        transform: hovering ? 'scale(1.01)' : 'scale(1)',
        transition: 'border-color var(--sc-t-fast), background var(--sc-t-fast), transform var(--sc-t-fast)',
        position: 'relative',
        userSelect: 'none',
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept.join(',')}
        multiple={multiple}
        onChange={handleChange}
        style={{ display: 'none' }}
        tabIndex={-1}
      />

      {/* Preview thumbnail */}
      {preview && (
        <div style={{ marginBottom: '0.75rem' }}>
          <img
            src={preview}
            alt="Preview"
            style={{
              maxHeight: 120,
              maxWidth: '100%',
              borderRadius: 8,
              objectFit: 'contain',
              margin: '0 auto',
              display: 'block',
            }}
          />
        </div>
      )}

      {/* File badge */}
      {fileName ? (
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            padding: '4px 10px',
            borderRadius: 20,
            background: 'color-mix(in srgb, var(--ui-accent) 15%, var(--ui-surface))',
            color: 'var(--ui-text)',
            fontSize: 13,
            fontWeight: 500,
            maxWidth: '100%',
          }}
        >
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>
            {fileName}
          </span>
          {onRemove && (
            <button
              onClick={(e) => { e.stopPropagation(); onRemove() }}
              aria-label="Remove file"
              style={{
                display: 'flex',
                alignItems: 'center',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--ui-text2)',
                padding: 0,
                lineHeight: 1,
              }}
            >
              <X size={14} />
            </button>
          )}
        </div>
      ) : (
        <>
          <UploadCloud
            size={32}
            strokeWidth={1.5}
            style={{ color: hovering ? 'var(--ui-accent)' : 'var(--ui-text2)', margin: '0 auto 0.5rem', display: 'block' }}
          />
          <p style={{ color: 'var(--ui-text)', fontSize: 14, fontWeight: 500 }}>{label}</p>
          {sublabel && (
            <p style={{ color: 'var(--ui-text2)', fontSize: 12, marginTop: 4 }}>{sublabel}</p>
          )}
          <p style={{ color: 'var(--ui-text2)', fontSize: 12, marginTop: 4 }}>
            {accept.join(', ')}
          </p>
        </>
      )}

      {/* Error / rejection message */}
      {(error || (rejected && rejectMsg)) && (
        <p style={{ color: 'var(--ui-danger)', fontSize: 12, marginTop: 8 }}>
          {error || rejectMsg}
        </p>
      )}
    </div>
  )
}
