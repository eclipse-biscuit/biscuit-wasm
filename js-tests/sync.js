import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import {
  authorizer,
  biscuit,
  block,
  Biscuit,
  initSync,
  KeyPair,
  PrivateKey,
} from "@biscuit-auth/biscuit-wasm/sync";
import { test } from "tape";

// necessary for esm support, see https://docs.rs/getrandom/latest/getrandom/#nodejs-es-module-support
if (parseInt(process.version.match(/v(\d+)\.(\d+)\.(\d+)/)[1], 10) <= 18) {
  globalThis.crypto = webcrypto;
}

const wasmBytes = readFileSync(
  new URL(
    "./node_modules/@biscuit-auth/biscuit-wasm/module/biscuit_bg.wasm",
    import.meta.url
  )
);

const wasmModule = new WebAssembly.Module(wasmBytes);
initSync(wasmModule);
initSync(wasmModule);

test("manual sync initialization works with a precompiled wasm module", function (t) {
  let pk = PrivateKey.fromString(
    "ed25519-private/473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97"
  );
  let root = KeyPair.fromPrivateKey(pk);

  let id = "1234";
  let token = biscuit`user(${id});`
    .build(root.getPrivateKey())
    .appendBlock(block`check if user($u)`);

  let parsedToken = Biscuit.fromBase64(token.toBase64(), root.getPublicKey());
  let policy = authorizer`allow if user(${id})`
    .buildAuthenticated(parsedToken)
    .authorize();

  t.equal(policy, 0, "authorization succeeded");
  t.end();
});
