const test = require('brittle')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

const HypercoreEncryption = require('./')

test('basic', async t => {
  const blindingKey = b4a.alloc(32, b4a.from([0x12, 0x34]))

  const block = new HypercoreEncryption(blindingKey, { getBlockKey })

  await block.load(1)
  block.setContext({ manifest: { version: 2 } })

  t.is(block.padding, 16)
  t.ok(block.seekable)

  const padding = 16

  const b0 = b4a.alloc(32, 0)
  const b1 = b4a.alloc(32, 1)
  const b2 = b4a.alloc(32, 2)

  const e0 = b4a.alloc(b0.byteLength + padding)
  const e1 = b4a.alloc(b1.byteLength + padding)
  const e2 = b4a.alloc(b2.byteLength + padding)

  e0.set(b0, padding)
  e1.set(b1, padding)
  e2.set(b2, padding)

  t.exception(() => block.encrypt(0, e0))

  await block.load(1)
  await block.encrypt(0, e0, 0)

  await block.load(2)
  await block.encrypt(1, e1, 1)

  await block.load(3)
  await block.encrypt(2, e2, 2)

  t.is(e0.byteLength, b0.byteLength + padding)
  t.is(e1.byteLength, b1.byteLength + padding)
  t.is(e2.byteLength, b2.byteLength + padding)

  await block.decrypt(0, e0)
  await block.decrypt(1, e1)
  await block.decrypt(2, e2)

  t.alike(e0.subarray(padding), b0)
  t.alike(e1.subarray(padding), b1)
  t.alike(e2.subarray(padding), b2)
})

test('legacy', async t => {
  const key = b4a.alloc(32, 0)
  const blindingKey = crypto.hash(key)

  const block = new HypercoreEncryption(blindingKey, { getBlockKey })

  block.setContext({ manifest: { version: 1 } })

  const b0 = b4a.alloc(32, 0)
  const b1 = b4a.alloc(32, 1)
  const b2 = b4a.alloc(32, 2)

  const e0 = b4a.alloc(b0.byteLength + 8)
  const e1 = b4a.alloc(b1.byteLength + 8)
  const e2 = b4a.alloc(b2.byteLength + 8)

  t.ok(block.seekable)

  e0.set(b0, 8)
  e1.set(b1, 8)
  e2.set(b2, 8)

  await block.encrypt(0, e0, 0)
  await block.encrypt(1, e1, 1)
  await block.encrypt(2, e2, 2)

  t.is(e0.byteLength, b0.byteLength + 8)
  t.is(e1.byteLength, b1.byteLength + 8)
  t.is(e2.byteLength, b2.byteLength + 8)

  await block.decrypt(0, e0)
  await block.decrypt(1, e1)
  await block.decrypt(2, e2)

  t.alike(e0.subarray(8), b0)
  t.alike(e1.subarray(8), b1)
  t.alike(e2.subarray(8), b2)
})

test('encryption provider can decrypt legacy', async t => {
  const legacyKey = b4a.alloc(32, 0)
  const blindingKey = crypto.hash(legacyKey)

  const legacy = new HypercoreEncryption(blindingKey, { getBlockKey })
  const block = new HypercoreEncryption(blindingKey, { getBlockKey })

  legacy.setContext({ manifest: { version: 1 } })

  const b0 = b4a.alloc(32, 0)
  const b1 = b4a.alloc(32, 1)
  const b2 = b4a.alloc(32, 2)
  const b3 = b4a.alloc(32, 3)

  const e0 = b4a.alloc(32 + 8)
  const e1 = b4a.alloc(32 + 8)
  const e2 = b4a.alloc(32 + 8)
  const e3 = b4a.alloc(32 + 16)

  // legacy scheme
  e0.set(b0, 8)
  e1.set(b1, 8)
  e2.set(b2, 8)

  await legacy.encrypt(0, e0, 0) // fork has to be pegged to 0
  await legacy.encrypt(1, e1, 0)
  await legacy.encrypt(2, e2, 0)

  await block.load(1)

  // updated scheme
  e3.set(b3, 16)

  await block.encrypt(3, e3, 3)

  t.is(e0.byteLength, b0.byteLength + 8)
  t.is(e1.byteLength, b1.byteLength + 8)
  t.is(e2.byteLength, b2.byteLength + 8)

  await block.decrypt(0, e0)
  await block.decrypt(1, e1)
  await block.decrypt(2, e2)
  await block.decrypt(3, e3)

  t.alike(e0.subarray(8), b0)
  t.alike(e1.subarray(8), b1)
  t.alike(e2.subarray(8), b2)
  t.alike(e3.subarray(16), b3)
})

test('sub class', async t => {
  class ContextEncryption extends HypercoreEncryption {
    constructor (blindingKey, opts = {}) {
      super(blindingKey, opts)
    }

    async _getBlockKey (id, context) {
      if (context.key === null) {
        throw new Error('Context has not been set')
      }

      await new Promise(process.nextTick)

      if (id === -1) id = 0
      return {
        id,
        version: 1,
        key: crypto.hash([b4a.alloc(32, id), context.key])
      }
    }
  }

  const blindingKey = crypto.hash(b4a.alloc(32, 0))
  const block = new ContextEncryption(blindingKey)

  const b0 = b4a.alloc(32, 0)
  const b1 = b4a.alloc(32, 1)
  const b2 = b4a.alloc(32, 2)
  const b3 = b4a.alloc(32, 3)

  const e0 = b4a.alloc(32 + 16)
  const e1 = b4a.alloc(32 + 16)
  const e2 = b4a.alloc(32 + 16)
  const e3 = b4a.alloc(32 + 16)

  e0.set(b0, 16)
  e1.set(b1, 16)
  e2.set(b2, 16)
  e3.set(b3, 16)

  await t.exception(block.encrypt(0, e0, 0))

  block.setContext({ key: b4a.alloc(32, 1) })

  await block.encrypt(0, e0, 0)
  await block.encrypt(1, e1, 0)
  await block.encrypt(2, e2, 0)
  await block.encrypt(3, e3, 3)

  await block.decrypt(0, e0)
  await block.decrypt(1, e1)
  await block.decrypt(2, e2)
  await block.decrypt(3, e3)

  t.alike(e0.subarray(16), b0)
  t.alike(e1.subarray(16), b1)
  t.alike(e2.subarray(16), b2)
  t.alike(e3.subarray(16), b3)
})

async function getBlockKey (id, context) {
  await Promise.resolve()

  if (context.manifest && context.manifest.version <= 1) id = 0

  if (id === -1) id = 0 // default

  if (id === 0) {
    return {
      id: 0,
      version: 0,
      key: b4a.alloc(32, 0)
    }
  }

  return {
    id,
    version: 1,
    key: b4a.alloc(32, id)
  }
}
