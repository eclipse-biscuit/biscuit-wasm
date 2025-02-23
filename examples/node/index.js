import {
  Biscuit,
  PrivateKey,
  KeyPair,
  authorizer,
  biscuit,
  block,
  check,
  fact,
  rule,
} from "@biscuit-auth/biscuit-wasm";
// necessary for esm support, see https://docs.rs/getrandom/latest/getrandom/#nodejs-es-module-support
import { webcrypto } from "node:crypto";

// this is not required anymore with node19+
if (parseInt(process.version.match(/v(\d+)\.(\d+)\.(\d+)/)[1], 10) <= 18) {
  globalThis.crypto = webcrypto;
}

let pk = PrivateKey.fromString(
  "473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97"
);
let root = KeyPair.fromPrivateKey(pk);

console.log("created the root key");

let id = 1234;
let biscuitBuilder = biscuit`user(${id});`;

for (let right of ["read", "write"]) {
  biscuitBuilder.addFact(fact`right(${right})`);
}

let thirdPartyPk = PrivateKey.fromString(
  "39c657dbd3f68b09bc8e5fd9887c7cb47a91d1d3883ffbc495ca790552398a92"
);
let thirdPartyRoot = KeyPair.fromPrivateKey(thirdPartyPk);
biscuitBuilder.addCheck(
  check`check if group("admin") trusting ${thirdPartyRoot.getPublicKey()}`
);

let token = biscuitBuilder
  .build(root.getPrivateKey()) // biscuit token
  .appendBlock(block`check if user($u)`); // attenuated biscuit token

let thirdPartyRequest = token.getThirdPartyRequest();
let thirdPartyBlock = thirdPartyRequest.createBlock(
  thirdPartyPk,
  block`group("admin");`
);

token = token.appendThirdPartyBlock(
  thirdPartyRoot.getPublicKey(),
  thirdPartyBlock
);

console.log(token.toString());
let serializedToken = token.toBase64();
console.log("created the token and signed it with the private key");
console.log(serializedToken);

let parsedToken = Biscuit.fromBase64(serializedToken, root.getPublicKey());
console.log("Parsed the token and verified its signatures with the public key");

let auth = authorizer`allow if user(${id})`.buildAuthenticated(parsedToken);

let policy = auth.authorizeWithLimits({
  max_facts: 10,
  max_iterations: 0,
  max_time_micro: 10000,
});
console.log("Authorized the token with the provided rules");
console.log("matched policy: " + policy);

let r1 = rule`u($id) <- user($id)`;
console.log(
  "The token authority block & authorization context can be queried:"
);
console.log(r1.toString());
let facts1 = auth.queryWithLimits(r1, {
  max_facts: 10,
  max_iterations: 0,
  max_time_micro: 10000,
});
console.log(facts1.map((f) => f.toString()));
let [queried_id] = facts1[0].terms();
console.log(queried_id);

let r2 = rule`g($id) <- group($id)`;
console.log(r2.toString());
console.log("Blocks are not queried by default:");
let facts2 = auth.queryWithLimits(r2, {
  max_facts: 10,
  max_iterations: 0,
  max_time_micro: 10000,
});
console.log(facts2.map((f) => f.toString()));

let r3 = rule`g($id) <- group($id) trusting ${thirdPartyRoot.getPublicKey()}`;
console.log("Third-party blocks can be queried by providing their public key");
console.log(r3.toString());
let facts3 = auth.queryWithLimits(r3, {
  max_facts: 10,
  max_iterations: 0,
  max_time_micro: 10000,
});
console.log(facts3.map((f) => f.toString()));
