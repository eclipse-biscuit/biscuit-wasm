import {
  authorizer,
  biscuit,
  block,
  check,
  fact,
  rule,
  policy,
  Biscuit,
  KeyPair,
  PrivateKey,
  PublicKey,
} from "@biscuit-auth/biscuit-wasm";
import { test } from "tape";
// necessary for esm support, see https://docs.rs/getrandom/latest/getrandom/#nodejs-es-module-support
import { webcrypto } from 'node:crypto'

// this is not required anymore with node19+
if (parseInt(process.version.match(/v(\d+)\.(\d+)\.(\d+)/)[1], 10) <= 18) {
  globalThis.crypto = webcrypto
}

test("keypair generation", function(t) {
  let pkStr =
    "76ac58cc933a3032d65e4d4faf99302fba381930486fd0ce1260654db25ca661";
  let pubStr =
    "9d0b36243c1dd2ceec188b81e798c6a7f2954fc02bd4c3913eb1885a2999278b";
  let pk = PrivateKey.fromString(pkStr);
  let root = KeyPair.fromPrivateKey(pk);
  t.equal(root.getPrivateKey().toString(), pkStr, "private key roundtrip");
  t.equal(root.getPublicKey().toString(), pubStr, "public key generation");
  t.end();
});

test("biscuit builder", function (t) {
  let userId = "1234";
  console.log("a");

  let builder = biscuit`user(${userId});`
    .addFact(fact`fact(${userId})`)
    .addRule(rule`u($id) <- user($id, ${userId})`)
    .addCheck(check`check if check(${userId})`)
    .setRootKeyId(1234);
  console.log("b");
  t.equal(
    builder.toString(),
    `// root key id: 1234
user("1234");
fact("1234");
u($id) <- user($id, "1234");
check if check("1234");
`,
    "builder roundtrip"
  );
  let pkStr =
    "76ac58cc933a3032d65e4d4faf99302fba381930486fd0ce1260654db25ca661";
  let pk = PrivateKey.fromString(pkStr);
  builder.build(pk);
  t.pass("building biscuit");
  t.end();
});

test("block builder", function (t) {
  let userId = "1234";
  let builder = block`check if user(${userId});`
    .addFact(fact`fact(${userId})`)
    .addRule(rule`u($id) <- user($id, ${userId})`)
    .addCheck(check`check if check(${userId})`);
  t.equal(
    builder.toString(),
    `fact("1234");
u($id) <- user($id, "1234");
check if user("1234");
check if check("1234");
`,
    "builder roundtrip"
  );
  t.end();
});

test("authorizer builder", function(t) {
  let userId = "1234";
  let builder = authorizer`allow if user(${userId});`;
  builder.addFact(fact`fact(${userId})`);
  builder.addRule(rule`u($id) <- user($id, ${userId})`);
  builder.addCheck(check`check if check(${userId})`);
  builder.addPolicy(policy`allow if check(${userId})`);

  builder.mergeBlock(block`check if true`);
  builder.merge(authorizer`deny if true`);

  // todo maybe the authorizer builder should have a toString
  // implementation that behaves more like the ones from
  // BlockBuilder and BiscuitBuilder
  t.equal(
    builder.toString(),
    `// Facts:
// origin: authorizer
fact("1234");

// Rules:
// origin: authorizer\nu($id) <- user($id, "1234");

// Checks:
// origin: authorizer
check if check("1234");
check if true;

// Policies:
allow if user("1234");
allow if check("1234");
deny if true;
`,
    "builder roundtrip"
  );
  t.end();
});

test("complete lifecycle", function(t) {
  let pk = PrivateKey.fromString(
    "473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97"
  );
  let root = KeyPair.fromPrivateKey(pk);

  let id = "1234";
  let biscuitBuilder = biscuit`user(${id});`;

  for (let right of ["read", "write"]) {
    biscuitBuilder.addFact(fact`right(${right})`);
  }

  let token = biscuitBuilder
    .build(root.getPrivateKey()) // biscuit token
    .appendBlock(block`check if user($u)`); // attenuated biscuit token
  let serializedToken = token.toBase64();

  let parsedToken = Biscuit.fromBase64(serializedToken, root.getPublicKey());
  let auth = authorizer`allow if user(${id})`;
  auth.addToken(parsedToken);

  let policy = auth.authorize();
  t.equal(policy, 0, "authorization suceeded");

  let otherKeyPair = new KeyPair();
  let r = rule`u($id) <- user($id), $id == ${id} trusting authority, ${otherKeyPair.getPublicKey()}`;
  let facts = auth.queryWithLimits(r, {
    max_time_micro: 100000
  });
  t.equal(facts.length, 1, "correct number of query results");
  t.equal(facts[0].toString(), `u("1234")`, "correct query result");
  t.end();
});

test("parameter injection", function(t) {
  t.equal(
    fact`fact(${1234})`.toString(),
    `fact(1234)`,
    "number"
  );
  t.equal(
    fact`fact(${"1234"})`.toString(),
    `fact("1234")`,
    "string"
  );
  t.equal(
    fact`fact(${true})`.toString(),
    `fact(true)`,
    "boolean"
  );
  t.equal(
    fact`fact(${new Date("2023-03-28T14:31:06Z")})`.toString(),
    `fact(2023-03-28T14:31:06Z)`,
    "date"
  );
  t.equal(
    fact`fact(${["a", 12, true]})`.toString(),
    `fact([12, "a", true])`,
    "set"
  );
  let bytes = new Uint8Array(Buffer.from([0, 170, 187]));
  t.equal(
    fact`fact(${bytes})`.toString(),
    `fact(hex:00aabb)`,
    "byte array"
  );
  let pubkey = PublicKey.fromString(
    "41e77e842e5c952a29233992dc8ebbedd2d83291a89bb0eec34457e723a69526"
  );
  t.equal(
    check`check if true trusting authority, ${pubkey}`.toString(),
    `check if true trusting authority, ed25519/41e77e842e5c952a29233992dc8ebbedd2d83291a89bb0eec34457e723a69526`,
    "public key"
  );

  t.equal(
    block`
    fact(${1234});
    fact(${"1234"});
    fact(${true});
    fact(${new Date("2023-03-28T14:31:06Z")});
    fact(${["a", 12, true, new Date("2023-03-28T14:31:06Z")]});
    fact(${bytes});
    check if true trusting authority, ${pubkey};`.toString(),
    `fact(1234);
fact("1234");
fact(true);
fact(2023-03-28T14:31:06Z);
fact([12, "a", 2023-03-28T14:31:06Z, true]);
fact(hex:00aabb);
check if true trusting authority, ed25519/41e77e842e5c952a29233992dc8ebbedd2d83291a89bb0eec34457e723a69526;
`,
    "complete block"
  );
  t.end();
});

test("third-party blocks", function(t) {
  let pk = PrivateKey.fromString(
    "473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97"
  );
  let root = KeyPair.fromPrivateKey(pk);

  let thirdPartyPk = PrivateKey.fromString(
    "39c657dbd3f68b09bc8e5fd9887c7cb47a91d1d3883ffbc495ca790552398a92"
  );
  let thirdPartyRoot = KeyPair.fromPrivateKey(thirdPartyPk);

  let id = "1234";
  let biscuitBuilder = biscuit`user(${id});`;

  for (let right of ["read", "write"]) {
    biscuitBuilder.addFact(fact`right(${right})`);
  }

  biscuitBuilder.addCheck(check`check if group("admin") trusting ${thirdPartyRoot.getPublicKey()}`);

  let token = biscuitBuilder
    .build(root.getPrivateKey()) // biscuit token
    .appendBlock(block`check if user($u)`); // attenuated biscuit token

  let thirdPartyRequest = token.getThirdPartyRequest();
  let thirdPartyBlock = thirdPartyRequest.createBlock(
    thirdPartyPk, block`group("admin");`
  );

  token = token.appendThirdPartyBlock(
    thirdPartyRoot.getPublicKey(),
    thirdPartyBlock
  );
  let serializedToken = token.toBase64();
  console.log(serializedToken);

  let parsedToken = Biscuit.fromBase64(serializedToken, root.getPublicKey());
  let auth = authorizer`allow if user(${id})`;
  auth.addToken(parsedToken);

  let policy = auth.authorize();
  t.equal(policy, 0, "authorization suceeded");

  let r1 = rule`g($group) <- group($group) trusting ${thirdPartyRoot.getPublicKey()}`;
  let facts = auth.queryWithLimits(r1, {
    max_time_micro: 100000
  });
  t.equal(facts.length, 1, "correct number of query results");
  t.equal(facts[0].toString(), `g("admin")`, "correct query result");

  let r2 = rule`g($group) <- group($group) trusting authority`;
  t.equal(auth.query(r2).length, 0, "correct number of query results");
  t.end();
});
