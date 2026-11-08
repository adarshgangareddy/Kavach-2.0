// Node 26 ships its own experimental localStorage, which hides jsdom's in tests.
// When it is missing, give the tests a plain in-memory Storage with the same methods.
if (!globalThis.localStorage) {
  class MemoryStorage {
    #items = new Map()
    getItem(key) { return this.#items.has(key) ? this.#items.get(key) : null }
    setItem(key, value) { this.#items.set(key, String(value)) }
    removeItem(key) { this.#items.delete(key) }
    clear() { this.#items.clear() }
    key(i) { return [...this.#items.keys()][i] ?? null }
    get length() { return this.#items.size }
  }
  const storage = new MemoryStorage()
  Object.defineProperty(globalThis, 'Storage', { value: MemoryStorage, configurable: true, writable: true })
  Object.defineProperty(globalThis, 'localStorage', { value: storage, configurable: true })
}

// jsdom does not implement matchMedia; framer-motion requires addListener / removeListener
if (typeof window !== 'undefined' && !window.matchMedia) {
  window.matchMedia = (query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })
}

// jsdom does not implement HTMLCanvasElement.prototype.getContext
if (typeof HTMLCanvasElement !== 'undefined') {
  const dummy2d = {
    clearRect: () => {},
    beginPath: () => {},
    arc: () => {},
    fill: () => {},
    fillRect: () => {},
    stroke: () => {},
    measureText: () => ({ width: 0 }),
  }
  HTMLCanvasElement.prototype.getContext = function (type) {
    if (type === '2d') return dummy2d
    return null
  }
}

// jsdom does not implement ResizeObserver or IntersectionObserver
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

if (typeof globalThis.IntersectionObserver === 'undefined') {
  globalThis.IntersectionObserver = class {
    constructor(callback) {
      this.callback = callback
    }
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

// Suppress known jsdom WebGL absence log from ogl
const origConsoleError = console.error
console.error = (...args) => {
  if (typeof args[0] === 'string' && args[0].includes('unable to create webgl context')) {
    return
  }
  origConsoleError(...args)
}




