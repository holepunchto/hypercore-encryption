# hypercore-encryption

Dyanmic Hypercore encryption provider

## Usage

```js
const HypercoreEncryption = require('hypercore-encryption')

const getEncryptionKey = async (id) => {
  // get key info corresponding to id...

  return {
    id, // encryption scheme
    payload // encryption key payload
  }
}

const encryption = new HypercoreEncryption(getEncryptionKey)

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

#### `const enc = new HypercoreEncryption(getEncryptionKey)`

Instantiate a new encryption provider.

Takes a hook with the signature:
```js
function getEncryptionKey (id) {
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

#### `const key = enc.get(id)`

Fetch the encryption key at `id`.

## License

Apache-2.0
