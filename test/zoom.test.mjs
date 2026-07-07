// zoom.js is plain CommonJS (no electron import), so it loads directly here.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { defaultZoomFor } from '../zoom.js'

const display = (width, height, scaleFactor) => ({ size: { width, height }, scaleFactor })

test('defaultZoomFor: 2x only for unscaled high-DPI Linux panels', () => {
  if (process.platform !== 'linux') {
    assert.equal(defaultZoomFor(display(3840, 2160, 1)), 1.0) // never scale off Linux
    return
  }
  assert.equal(defaultZoomFor(display(1920, 1080, 1)), 1.0) // 1080p — must stay 1x (the bug)
  assert.equal(defaultZoomFor(display(2560, 1440, 1)), 1.0) // 1440p — not dense enough
  assert.equal(defaultZoomFor(display(3838, 1931, 1)), 2.0) // the dev machine — stays 2x
  assert.equal(defaultZoomFor(display(3840, 2160, 1)), 2.0) // 4K unscaled → tiny → 2x
  assert.equal(defaultZoomFor(display(2880, 1800, 1)), 2.0) // retina-class laptop panel
  assert.equal(defaultZoomFor(display(1920, 1080, 2)), 1.0) // 4K the OS already scales (DIP size)
})
