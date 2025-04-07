const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const c = require('compact-encoding')
const b4a = require('b4a')

const [NS_BLOCK_KEY] = crypto.namespace('hypercore-encryption', 1)

const LEGACY_MANIFEST_VERSION = 1
const TYPES = {
  LEGACY: 0,
  BLOCK: 1
}

const nonce = b4a.allocUnsafe(sodium.crypto_stream_NONCEBYTES)

class LegacyProvider {
  static version = TYPES.LEGACY
  static padding = 8

  constructor (blockKey) {
    this.blockKey = blockKey
    this.blindingKey = b4a.allocUnsafe(sodium.crypto_stream_KEYBYTES)

    this.seekable = true
    this.padding = LegacyProvider.padding
    this.version = LegacyProvider.version

    sodium.crypto_generichash(this.blindingKey, this.blockKey)
  }

  load () {
    // compat
  }

  setContext () {
    // compat
  }

  encrypt (index, block, fork) {
    return LegacyProvider.encrypt(index, block, fork, this.blockKey, this.blindingKey)
  }

  decrypt (index, block) {
    return LegacyProvider.decrypt(index, block, this.blockKey)
  }

  static encrypt (index, block, fork, key, blindingKey) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    c.uint64.encode({ start: 0, end: 8, buffer: padding }, fork)
    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    // Zero out any previous padding
    nonce.fill(0, 8)

    if (!blindingKey) blindingKey = crypto.hash(key)

    // Blind the fork ID, possibly risking reusing the nonce on a reorg of the
    // Hypercore. This is fine as the blinding is best-effort and the latest
    // fork ID shared on replication anyway
    encrypt(padding, nonce, blindingKey)

    nonce.set(padding, 8, 8 + padding.byteLength)

    // The combination of a (blinded) fork ID and a block index is unique for a
    // given Hypercore and is therefore a valid nonce for encrypting the block
    encrypt(block, nonce, key)
  }

  static decrypt (index, block, key) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    setNonce(index)

    nonce.set(padding, 8)
    nonce.fill(0, 8 + padding.byteLength)

    // Decrypt the block using the blinded fork ID
    decrypt(block, nonce, key)
  }
}

class BlockProvider {
  static version = TYPES.BLOCK
  static padding = 16

  static encrypt (index, block, fork, id, key, blindingKey) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    // Unkeyed hash of block as we blind it later
    sodium.crypto_generichash(padding, block)

    // Encode padding
    c.uint32.encode({ start: 0, end: 4, buffer: padding }, id)
    c.uint32.encode({ start: 4, end: 8, buffer: padding }, fork)

    setNonce(index)

    // Blind key id, fork id and block hash
    encrypt(padding, nonce, blindingKey)

    nonce.set(padding, 8)

    // The combination of index, key id, fork id and block hash is very likely
    // to be unique for a given Hypercore and therefore our nonce is suitable
    encrypt(block, nonce, key)
  }

  static decrypt (index, block, key) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    setNonce(index)

    nonce.set(padding, 8)

    // Decrypt the block using the full nonce
    decrypt(block, nonce, key)
  }
}

class HypercoreEncryption {
  static KEYBYTES = sodium.crypto_stream_KEYBYTES

  constructor (blindingKey, opts = {}) {
    this.blindingKey = blindingKey

    this.context = {
      manifest: null,
      key: null
    }

    this.current = null
    this.keys = new Map()

    if (opts.getBlockKey) {
      this._getBlockKey = opts.getBlockKey
    }
  }

  get padding () {
    if (this.manifestVersion === -1) return 0
    if (this.manifestVersion <= LEGACY_MANIFEST_VERSION) return LegacyProvider.padding
    return BlockProvider.padding
  }

  get seekable () {
    return true
  }

  get version () {
    return this.current ? this.current.version : -1
  }

  get manifestVersion () {
    return this.context.manifest ? this.context.manifest.version : -1
  }

  async load (id) {
    this.current = await this._get(id)
  }

  async _get (id) {
    if (this.keys.has(id)) return this.keys.get(id)

    const info = await this._getBlockKey(id, this.context)
    if (!info) throw new Error('Unrecognised encryption id')

    this.keys.set(id, info)

    return info
  }

  _getBlockKey () {
    // must be providede by user
    throw new Error('Not implemented')
  }

  setContext ({ key, manifest } = {}) {
    if (key && !this.context.key) this.context.key = key
    if (manifest && !this.context.manifest) this.context.manifest = manifest
  }

  _parseId (index, block) {
    const id = b4a.alloc(4)
    id.set(block.subarray(0, 4))

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)
    nonce.fill(0, 8)

    encrypt(id, nonce, this.blindingKey)

    return c.uint32.decode({ start: 0, end: 4, buffer: id })
  }

  async encrypt (index, block, fork) {
    if (this.current === null) {
      await this.load(-1)
    }

    if (this.current === null) {
      throw new Error('Encryption provider has not been loaded')
    }

    if (this.manifestVersion !== -1 && this.manifestVersion <= LEGACY_MANIFEST_VERSION) {
      return LegacyProvider.encrypt(index, block, fork, this.current.key, this.blindingKey)
    }

    switch (this.current.version) {
      case BlockProvider.version: {
        return BlockProvider.encrypt(index, block, fork, this.current.id, this.current.key, this.blindingKey)
      }
    }

    throw new Error('Unknown encryption scheme')
  }

  async decrypt (index, block) {
    if (this.manifestVersion !== -1 && this.manifestVersion <= LEGACY_MANIFEST_VERSION) {
      return LegacyProvider.decrypt(index, block, this.current.key)
    }

    const id = this._parseId(index, block)
    const info = await this._get(id)

    const { version, key } = info

    switch (version) {
      case LegacyProvider.version:
        // beware: only safe to use new encryption
        // on old data if the core has NEVER forked
        return LegacyProvider.decrypt(index, block, key)

      case BlockProvider.version:
        return BlockProvider.decrypt(index, block, key)

      default:
        throw new Error('Unrecognised version')
    }
  }

  static isHypercoreEncryption (enc) {
    if (enc instanceof HypercoreEncryption) return true
    if (enc instanceof LegacyProvider) return true
    return false
  }

  static getBlockKey (hypercoreKey, encryptionKey) {
    return getBlockKey(hypercoreKey, encryptionKey)
  }

  static createLegacyProvider (blockKey) {
    return new LegacyProvider(blockKey)
  }

  static encrypt (index, block, fork, version, id, key, blindingKey) {
    switch (version) {
      case LegacyProvider.version:
        return LegacyProvider.encrypt(index, block, fork, key, blindingKey)

      case BlockProvider.version: {
        return BlockProvider.encrypt(index, block, fork, id, key, blindingKey)
      }
    }

    throw new Error('Unknown encryption scheme')
  }
}

module.exports = HypercoreEncryption

function getBlockKey (hypercoreKey, encryptionKey) {
  const key = b4a.allocUnsafe(sodium.crypto_stream_KEYBYTES)
  sodium.crypto_generichash_batch(key, [NS_BLOCK_KEY, hypercoreKey, encryptionKey])
  return key
}

function setNonce (index) {
  c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

  // Zero out any previous padding.
  nonce.fill(0, 8)
}

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
