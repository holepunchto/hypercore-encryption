# hypercore-encryption

Dynamic Hypercore encryption provider

## Usage

```js
const HypercoreEncryption = require('hypercore-encryption')

const getEncryptionKey = async (id) => {
  // get key info corresponding to id...

  return {
    id, // encryption scheme
    encryptionKey // encryption key
  }
}

const encryption = new HypercoreEncryption(getEncryptionKey)

const core = new Hypercore(storage, {
  encryption: encryption.createEncryptionProvider({
    transform (ctx, entropy, compat) {
      return {
        block: deriveBlockKey(entropy),
        hash: deriveHashKey(entropy)
      }
    }
  })
})

await core.ready()
await core.append('encrypt with key')
```

## API

#### `const enc = new HypercoreEncryption(getEncryptionKey)`

Instantiate a new encryption provider.

Takes a hook with the signature:
```js
async function getEncryptionKey (id) {
  // if id is passed as -1, the module expects the latest key

  return {
    id, // encryption id
    encryptionKey // encryption key
  }
}

```

#### `const provider = enc.createEncryptionProvider({ transform, compat })`

Create an encryption provider.

```js
{
  function transform (ctx, entropy, compat) {
    // implement custom block key derivation
    // compat will be passed as true when a compat is expected

    // block key and hash/blinding key should be distinct
    return {
      block,
      hash, // not required for compat keys
      blinding // only required for compat keys
    }
  },
  function compat (ctx, index) {
    // return true or false whether a compat key is expected
  }
}
```

See [hypercore encryption](https://github.com/holepunchto/hypercore/blob/main/lib/default-encryption.js) for  details on compat encryption.

#### `enc.clear()`

Clear any cached keys.

#### `const { id, encryptionKey } = await enc.get(id)`

Fetch the encryption key at `id`.

If `-1` is passed as `id`, the latest available key will be returned.

## License

Apache-2.0
