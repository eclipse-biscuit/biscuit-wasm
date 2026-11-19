# Biscuit-wasm

This repo is part of the [eclipse biscuit](https://github.com/biscuit-auth/biscuit) project.

This library wraps the [Rust implementation](https://github.com/biscuit-auth) of [Eclipse Biscuit tokens](https://www.biscuitsec.org) in WebAssembly, for usage in NodeJS and browsers.

It provides both EcmaScript and CommonJS modules, along with TypeScript type definitions.

## Usage

Add this dependency to your `package.json`:

```json
{
  "dependencies": {
    "@biscuit-auth/biscuit-wasm": "0.6.0"
  }
}
```

Usage examples are available [here](https://doc.biscuitsec.org/usage/nodejs).

### Node

_see the example code in examples/node_

The `node` executable must be started with the [`--experimental-wasm-modules` flag](https://nodejs.org/api/esm.html#wasm-modules).

### In browser

_see the example code in examples/frontend_

Importing a WebAssembly library with a bundler can take a bit of configuration. We have a working example with
Webpack, and would welcome example configuration for other bundlers:

```javascript
const path = require("path");

module.exports = {
  entry: "./index.js",
  output: {
    filename: "index.js",
    path: path.resolve(__dirname, "dist"),
  },
  experiments: {
    asyncWebAssembly: true,
  },
};
```

### Cloudflare Workers / workerd

Cloudflare Workers and other `workerd`-style runtimes import `.wasm` assets as
precompiled `WebAssembly.Module` objects instead of relying on bundler-managed
WASM module imports. The default package entry remains the `wasm-pack --target bundler`
output for browser and Node bundler use cases, but the package now also exposes
runtime-specific entrypoints for manual initialization:

```javascript
import {
  Biscuit,
  KeyPair,
  PrivateKey,
  authorizer,
  biscuit,
  block,
} from "@biscuit-auth/biscuit-wasm/workerd";
```

If your tooling does not honor the `workerd` export condition automatically, you
can import the explicit `@biscuit-auth/biscuit-wasm/workerd` subpath.

For runtimes that can provide a `WebAssembly.Module` directly, use the `sync`
entrypoint and initialize the package yourself:

```javascript
import { readFileSync } from "node:fs";
import {
  Biscuit,
  PrivateKey,
  authorizer,
  biscuit,
  block,
  initSync,
} from "@biscuit-auth/biscuit-wasm/sync";

const wasmBytes = readFileSync(
  new URL("./node_modules/@biscuit-auth/biscuit-wasm/module/biscuit_bg.wasm", import.meta.url)
);
initSync(new WebAssembly.Module(wasmBytes));
```

## License

Licensed under the Apache 2.0 License.

Copyright 2021 Geoffroy Couprie
