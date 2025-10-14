const test = require('brittle')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

const HypercoreEncryption = require('./')

test('basic', async t => {
  const encryption = new HypercoreEncryption(getBlockKey)

  const block = encryption.createEncryptionProvider()

  const padding = 8

  const b0 = b4a.alloc(32, 0)
  const b1 = b4a.alloc(32, 1)
  const b2 = b4a.alloc(32, 2)

  const e0 = b4a.alloc(b0.byteLength + padding)
  const e1 = b4a.alloc(b1.byteLength + padding)
  const e2 = b4a.alloc(b2.byteLength + padding)

  e0.set(b0, padding)
  e1.set(b1, padding)
  e2.set(b2, padding)

  const ctx = { key: b4a.alloc(32, 0xff) }

  await block.encrypt(0, e0, 0, ctx)
  await block.encrypt(1, e1, 1, ctx)
  await block.encrypt(2, e2, 2, ctx)

  t.is(e0.byteLength, b0.byteLength + padding)
  t.is(e1.byteLength, b1.byteLength + padding)
  t.is(e2.byteLength, b2.byteLength + padding)

  await block.decrypt(0, e0, ctx)
  await block.decrypt(1, e1, ctx)
  await block.decrypt(2, e2, ctx)

  t.alike(e0.subarray(padding), b0)
  t.alike(e1.subarray(padding), b1)
  t.alike(e2.subarray(padding), b2)
})

test('transform', async t => {
  const encryption = new HypercoreEncryption(getBlockKey)

  const transform1 = generateTransform(b4a.alloc(32, 1))
  const transform2 = generateTransform(b4a.alloc(32, 2))

  const block1 = encryption.createEncryptionProvider({ transform: transform1 })
  const block2 = encryption.createEncryptionProvider({ transform: transform2 })

  const b = b4a.alloc(32, 0)
  const e1 = b4a.alloc(32 + 8)
  const e2 = b4a.alloc(32 + 8)

  e1.set(b, 8)
  e2.set(b, 8)

  const ctx = { key: b4a.alloc(32, 1) }

  await block1.encrypt(0, e1, 0, ctx)
  await block2.encrypt(0, e2, 0, ctx)

  t.unlike(e1.subarray(8), b)
  t.unlike(e2.subarray(8), b)
  t.unlike(e1.subarray(8), e2)

  const e2copy = b4a.from(e2)
  await block1.decrypt(0, e2copy, ctx)

  t.unlike(e2copy.subarray(8), b)

  await block1.decrypt(0, e1, ctx)
  await block2.decrypt(0, e2, ctx)

  t.alike(e1.subarray(8), b)
  t.alike(e2.subarray(8), b)
})

async function getBlockKey (id, ctx) {
  if (id === -1) id = (Math.random() * 32) | 0

  await Promise.resolve()

  if (ctx && ctx.manifest && ctx.manifest.version <= 1) id = 0

  if (id === -1) id = 0 // default

  if (id === 0) {
    return {
      id: 0,
      encryptionKey: b4a.alloc(32, 0)
    }
  }

  return {
    id,
    encryptionKey: b4a.alloc(32, id)
  }
}

function generateTransform (namespace) {
  return function (ctx, entropy) {
    const block = crypto.hash([namespace, entropy])
    return {
      block,
      hash: crypto.hash(block)
    }
  }
}
