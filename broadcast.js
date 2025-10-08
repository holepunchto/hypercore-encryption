const sodium = require('sodium-universal')
const c = require('compact-encoding')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

const [NS_NONCE, NS_KEYPAIR_SEED] = crypto.namespace('hypercore-encryption/broadcast', 2)

// ephemeral state
const PayloadArray = c.array(c.buffer)

const EncryptionPayload = {
  preencode (state, m) {
    c.buffer.preencode(state, m.nonce)
    c.fixed32.preencode(state, m.publicKey)
    PayloadArray.preencode(state, m.payload)
  },
  encode (state, m) {
    c.buffer.encode(state, m.nonce)
    c.fixed32.encode(state, m.publicKey)
    PayloadArray.encode(state, m.payload)
  },
  decode (state) {
    return {
      nonce: c.buffer.decode(state),
      publicKey: c.fixed32.decode(state),
      payload: PayloadArray.decode(state)
    }
  }
}

module.exports = class BroadcastEncryption {
  static unpack (data, recipientSecretKey) {
    const nonce = b4a.allocUnsafe(sodium.crypto_box_NONCEBYTES)
    const secretKey = b4a.allocUnsafe(sodium.crypto_box_SECRETKEYBYTES)

    const { publicKey, payload } = c.decode(EncryptionPayload, data)

    const key = b4a.alloc(payload[0].byteLength - sodium.crypto_box_MACBYTES)

    sodium.crypto_generichash_batch(nonce, [NS_NONCE, publicKey])
    sodium.crypto_sign_ed25519_sk_to_curve25519(secretKey, recipientSecretKey)

    for (const ciphertext of payload) {
      if (sodium.crypto_box_open_easy(key, ciphertext, nonce, publicKey, secretKey)) {
        return key
      }
    }

    return null
  }

  static pack (data, recipients) {
    const nonce = b4a.allocUnsafe(sodium.crypto_box_NONCEBYTES)
    const secretKey = b4a.allocUnsafe(sodium.crypto_box_SECRETKEYBYTES)
    const publicKey = b4a.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES)
    const recipientKey = b4a.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES)

    const seed = crypto.hash([NS_KEYPAIR_SEED, data])

    sodium.crypto_box_seed_keypair(publicKey, secretKey, seed)
    sodium.crypto_generichash_batch(nonce, [NS_NONCE, publicKey])

    const payload = {
      publicKey,
      payload: []
    }

    for (const recipient of recipients) {
      if (recipient === null) continue

      const enc = b4a.alloc(data.byteLength + sodium.crypto_box_MACBYTES)

      sodium.crypto_sign_ed25519_pk_to_curve25519(recipientKey, recipient)
      sodium.crypto_box_easy(enc, data, nonce, recipientKey, secretKey)

      payload.payload.push(enc)
    }

    return c.encode(EncryptionPayload, payload)
  }

  static verify (ciphertext, data, recipients) {
    const nonce = b4a.allocUnsafe(sodium.crypto_box_NONCEBYTES)
    const secretKey = b4a.allocUnsafe(sodium.crypto_box_SECRETKEYBYTES)
    const publicKey = b4a.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES)
    const recipientKey = b4a.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES)

    const seed = crypto.hash([NS_KEYPAIR_SEED, data])

    sodium.crypto_box_seed_keypair(publicKey, secretKey, seed)
    sodium.crypto_generichash_batch(nonce, [NS_NONCE, publicKey])

    const received = c.decode(EncryptionPayload, ciphertext)

    if (!b4a.equals(publicKey, received.publicKey)) return false

    const expected = b4a.alloc(data.byteLength + sodium.crypto_box_MACBYTES)

    for (const target of recipients) {
      sodium.crypto_sign_ed25519_pk_to_curve25519(recipientKey, target)
      sodium.crypto_box_easy(expected, data, nonce, recipientKey, secretKey)

      let found = false

      for (const ciphertext of received.payload) {
        if (b4a.equals(ciphertext, expected)) {
          found = true
          break
        }
      }

      if (!found) return false
    }

    return true
  }
}
