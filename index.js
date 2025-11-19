const DefaultEncryption = require('hypercore/lib/default-encryption.js')
const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const c = require('compact-encoding')
const b4a = require('b4a')

const [NS_HASH_KEY] = crypto.namespace('hypercore-encryption', 1)

const nonce = b4a.alloc(sodium.crypto_stream_NONCEBYTES)
const hash = nonce.subarray(0, sodium.crypto_generichash_BYTES_MIN)

class EncryptionProvider {
  constructor (encryption, opts = {}) {
    this.encryption = encryption

    this._transform = opts.transform || defaultTransform
    this._compat = opts.compat || defaultCompat
  }

  padding () {
    return HypercoreEncryption.PADDING
  }

  async get (id, ctx) {
    const desc = await this.encryption.get(id)

    if (!desc.encryptionKey) {
      throw new Error('No encryption details were provided')
    }

    const { block, hash } = await this._transform(ctx, desc.encryptionKey, false)

    return {
      id: desc.id,
      block,
      hash
    }
  }

  async encrypt (index, block, fork, ctx) {
    if (this._compat(ctx, index)) {
      const keys = await this._transform(ctx, null, true)
      return DefaultEncryption.encrypt(index, block, fork, keys.block, keys.blinding)
    }

    const keys = await this.get(-1, ctx)

    encryptBlock(index, block, keys.id, keys.block, keys.hash)
  }

  async decrypt (index, block, ctx) {
    if (this._compat(ctx, index)) {
      const keys = await this._transform(ctx, null, true)
      return DefaultEncryption.decrypt(index, block, keys.block)
    }

    const padding = block.subarray(0, HypercoreEncryption.PADDING)
    block = block.subarray(HypercoreEncryption.PADDING)

    const type = padding[0]
    switch (type) {
      case 0:
        return block // unencrypted

      case 1:
        break

      default:
        throw new Error('Unrecognised encryption type')
    }

    const id = c.uint32.decode({ start: 4, end: 8, buffer: padding })

    const keys = await this.get(id, ctx)

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)
    nonce.set(padding, 8)

    // Decrypt the block using the full nonce
    decrypt(block, nonce, keys.block)
  }
}

class HypercoreEncryption {
  static PADDING = 8

  constructor (getEncryptionKey) {
    this.getEncryptionKey = getEncryptionKey
    this._cache = new Map()
  }

  createEncryptionProvider ({ transform, compat } = {}) {
    return new EncryptionProvider(this, { transform, compat })
  }

  clear () {
    this._cache.clear()
  }

  async get (encryptionId) {
    if (this._cache.has(encryptionId)) {
      return {
        id: encryptionId,
        encryptionKey: this._cache.get(encryptionId)
      }
    }

    const { id, encryptionKey } = await this.getEncryptionKey(encryptionId)

    this._cache.set(id, encryptionKey)

    return { id, encryptionKey }
  }
}

module.exports = HypercoreEncryption

function encrypt (block, nonce, key) {
  sodium.crypto_stream_xor(
    block,
    block,
    nonce,
    key
  )
}

function decrypt (block, nonce, key) {
  return encrypt(block, nonce, key) // symmetric
}

function blockhash (block, padding, hashKey) {
  sodium.crypto_generichash(hash, block, hashKey)
  padding.set(hash.subarray(0, 8)) // copy first 8 bytes of hash
  hash.fill(0) // clear nonce buffer
}

function encryptBlock (index, block, id, blockKey, hashKey) {
  const padding = block.subarray(0, HypercoreEncryption.PADDING)
  block = block.subarray(HypercoreEncryption.PADDING)

  blockhash(block, padding, hashKey)
  c.uint32.encode({ start: 4, end: 8, buffer: padding }, id)

  c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

  padding[0] = 1 // version in plaintext

  nonce.set(padding, 8)

  // The combination of index, key id, fork id and block hash is very likely
  // to be unique for a given Hypercore and therefore our nonce is suitable
  encrypt(block, nonce, blockKey)
}

function defaultTransform (ctx, encryptionKey) {
  return {
    block: encryptionKey,
    hash: crypto.hash([NS_HASH_KEY, encryptionKey])
  }
}

function defaultCompat () {
  return false
}
