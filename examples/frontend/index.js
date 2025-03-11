import {
  Biscuit,
  PrivateKey,
  KeyPair,
  Fact,
  Rule,
  biscuit,
  authorizer,
  block,
} from "@biscuit-auth/biscuit-wasm";

let keypair = new KeyPair();

let pk = PrivateKey.fromString(
  "ed25519-private/473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97"
);
let root = KeyPair.fromPrivateKey(pk);

console.log("created the root key");

let id = 1234;
let biscuitBuilder = biscuit`user(${id});`;

for (let right of ["read", "write"]) {
  biscuitBuilder.merge(block`right(${right})`);
}

let token = biscuitBuilder
  .build(root.getPrivateKey()) // biscuit token
  .appendBlock(block`check if user($u)`); // attenuated biscuit token
console.log(token);
let serializedToken = token.toBase64();
console.log("created the token and signed it with the private key");
console.log(serializedToken);

let parsedToken = Biscuit.fromBase64(serializedToken, root.getPublicKey());
console.log("Parsed the token and verified its signatures with the public key");

let auth = authorizer`allow if user(${id})`.buildAuthenticated(parsedToken);

let policy = auth.authorize();
console.log("Authorized the token with the provided rules");
console.log("matched policy: " + policy);

let facts = auth.query(Rule.fromString("u($id) <- user($id)"));
console.log(
  "Queried the token (and the authorization context) and got the following results"
);

for (let f of facts) {
  console.log(f.toString());
}
