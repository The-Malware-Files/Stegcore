// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { create } from 'zustand'

interface DragStore {
  isDraggingOver: boolean
  draggedFiles: File[]
  setDragging: (v: boolean) => void
  setDraggedFiles: (files: File[]) => void
  reset: () => void
}

export const useDragStore = create<DragStore>((set) => ({
  isDraggingOver: false,
  draggedFiles: [],

  setDragging: (isDraggingOver) => set({ isDraggingOver }),
  setDraggedFiles: (draggedFiles) => set({ draggedFiles }),
  reset: () => set({ isDraggingOver: false, draggedFiles: [] }),
}))
