# hypercore-encryption

Dyanmic Hypercore encryption provider

## Usage

```js
const HypercoreEncryption = require('hypercore-encryption')

const encryption = new HypercoreEncryption({
  namespace,
  async fetch (id) {
    // get key info corresponding to id...

    return {
      id, // encryption scheme
      payload // encryption key payload
    }
  }
})

const core = new Hypercore(storage, {
  encryption: encryption.createEncryptionProvider({
    transform (entropy) {
      return crypto.hash([NAMESPACE, entropy]) // optionally hash
    }
  })
})

await core.ready()
await core.append('encrypt with key')
```

## API

#### `const enc = new HypercoreEncryption({ fetch, namespace })`

Instantiate a new encryption provider. Optionally pass a `preopen` promise that resolves to a key id to be loaded initially.

Any `namespace` passed in will be mixed into all generated encryption keys.

Provide a hooks with the signature:
```js
function fetch (id) {
  // if id is passed as -1, the module expects the latest key

  return {
    id, // encryption id
    entropy // entropy
  }
}

```

#### `const provider = enc.createEncryptionProvider({ transform, compat })`

Create an encryption provider.

```
{
  transform (ctx, entropy) {
    // implement custom block key derivation
    // entropy will be passed as null when a compat
    // is expected
  },
  compat (ctx, index) {
    // return true or false whether a compat key is expected
  }
}
```

#### `enc.clear()`

Clear any cached keys.

#### `const namespace = HypercoreEncryption.namespace(seed)`

Helper to generate namespaces.

#### `const blockKey = HypercoreEncryption.getBlockKey(namespace, entropy, hypercoreKey)`

Helper to generate namespaced block keys.

#### `const ciphetext = HypercoreEncryption.broadcastEncrypt(plaintext, recipients)`

Helper to broadcast encrypt data to `recipients`.

#### `const plaintext = HypercoreEncryption.broadcastEncrypt(ciphertext, recipientSecretKey)`

Helper to decrypt broadcast ciphertexts.

#### `const verified = HypercoreEncryption.broadcastVerify(ciphertext, data, recipients)`

Helper to verify broadcast ciphertexts. Returns `true` if there exists a valid encryption of `data` to each `recipient` key or `false` otherwise

## License

Apache-2.0
