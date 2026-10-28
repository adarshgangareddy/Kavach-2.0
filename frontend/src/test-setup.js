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
