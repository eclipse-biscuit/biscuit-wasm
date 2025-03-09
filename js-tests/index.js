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
  SignatureAlgorithm,
} from "@biscuit-auth/biscuit-wasm";
import { test } from "tape";
// necessary for esm support, see https://docs.rs/getrandom/latest/getrandom/#nodejs-es-module-support
import { webcrypto } from "node:crypto";

// this is not required anymore with node19+
if (parseInt(process.version.match(/v(\d+)\.(\d+)\.(\d+)/)[1], 10) <= 18) {
  globalThis.crypto = webcrypto;
}

test("keypair generation", function (t) {
  let pkStr =
    "ed25519/76ac58cc933a3032d65e4d4faf99302fba381930486fd0ce1260654db25ca661";
  let pubStr =
    "ed25519/9d0b36243c1dd2ceec188b81e798c6a7f2954fc02bd4c3913eb1885a2999278b";
  let pk = PrivateKey.fromString(pkStr);
  let root = KeyPair.fromPrivateKey(pk);
  t.equal(root.getPrivateKey().toString(), pkStr, "private key roundtrip");
  t.equal(root.getPublicKey().toString(), pubStr, "public key generation");
  t.end();
});

test("ECDSA keypair generation", function (t) {
  let kp = new KeyPair(SignatureAlgorithm.Secp256r1);
  console.log(kp.getPublicKey().toString());
  t.ok(kp.getPublicKey().toString().startsWith("secp256r1/"), "public key prefix");

  let kp2 = new KeyPair(SignatureAlgorithm.Ed25519);
  console.log(kp2.getPublicKey().toString());
  t.ok(kp2.getPublicKey().toString().startsWith("ed25519/"), "public key prefix");

  let kp3 = new KeyPair();
  console.log(kp3.getPublicKey().toString());
  t.ok(kp3.getPublicKey().toString().startsWith("ed25519/"), "public key prefix");
  
  let id = "1234";
  let biscuitBuilder = biscuit`user(${id});`;

  biscuitBuilder.setRootKeyId(1234);
  let token = biscuitBuilder
    .build(kp.getPrivateKey()) // biscuit token
    .appendBlock(block`check if user($u)`);
  let serializedToken = token.toBase64();

  let parsedToken = Biscuit.fromBase64(serializedToken, kp.getPublicKey());
  let auth = authorizer`allow if user(${id})`.buildAuthenticated(parsedToken);

  let policy = auth.authorize();
  t.equal(policy, 0, "authorization suceeded");
  t.end();
});

test("biscuit builder", function (t) {
  let userId = "1234";

  let builder = biscuit`user(${userId});`;
  builder.addFact(fact`fact(${userId})`);
  builder.addRule(rule`u($id) <- user($id, ${userId})`);
  builder.addCheck(check`check if check(${userId})`);
  builder.setRootKeyId(1234);
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
    "ed25519/76ac58cc933a3032d65e4d4faf99302fba381930486fd0ce1260654db25ca661";
  let pk = PrivateKey.fromString(pkStr);
  builder.build(pk);
  t.pass("building biscuit");
  t.end();
});

test("block builder", function (t) {
  let userId = "1234";
  let builder = block`check if user(${userId});`;
  builder.addFact(fact`fact(${userId})`);
  builder.addRule(rule`u($id) <- user($id, ${userId})`);
  builder.addCheck(check`check if check(${userId})`);
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

test("authorizer builder", function (t) {
  let userId = "1234";
  let builder = authorizer`allow if user(${userId});`;
  builder.addFact(fact`fact(${userId})`);
  builder.addRule(rule`u($id) <- user($id, ${userId})`);
  builder.addCheck(check`check if check(${userId})`);
  builder.addPolicy(policy`allow if check(${userId})`);
  builder.addCheck(check`check if true`);
  builder.addPolicy(policy`deny if true`);

  // todo maybe the authorizer builder should have a toString
  // implementation that behaves more like the ones from
  // BlockBuilder and BiscuitBuilder
  t.equal(
    builder.toString(),
    `fact("1234");

u($id) <- user($id, "1234");

check if check("1234");
check if true;

allow if user("1234");
allow if check("1234");
deny if true;
`,
    "builder roundtrip"
  );
  t.end();
});

test("complete lifecycle", function (t) {
  let pk = PrivateKey.fromString(
    "ed25519/473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97"
  );
  let root = KeyPair.fromPrivateKey(pk);

  let id = "1234";
  let biscuitBuilder = biscuit`user(${id});`;

  for (let right of ["read", "write"]) {
    biscuitBuilder.addFact(fact`right(${right})`);
  }

  biscuitBuilder.setRootKeyId(1234);
  let token = biscuitBuilder
    .build(root.getPrivateKey()) // biscuit token
    .appendBlock(block`check if user($u)`); // attenuated biscuit token
  let serializedToken = token.toBase64();

  let parsedToken = Biscuit.fromBase64WithProvider(serializedToken, function(key_id) {
    if (key_id === 1234) {
      console.log("key", root.getPublicKey().toString());
      return root.getPublicKey().toString();
    }
    throw new Error("Unknown key id: " + key_id);
  });
  let auth = authorizer`allow if user(${id})`.buildAuthenticated(parsedToken);

  let policy = auth.authorize();
  t.equal(policy, 0, "authorization suceeded");

  let otherKeyPair = new KeyPair();
  let r = rule`u($id) <- user($id), $id == ${id} trusting authority, ${otherKeyPair.getPublicKey()}`;
  let facts = auth.queryWithLimits(r, {
    max_time_micro: 100000,
  });
  t.equal(facts.length, 1, "correct number of query results");
  t.equal(facts[0].toString(), `u("1234")`, "correct query result");

  let r2 = rule`test(1, "a", 2024-04-28T16:31:06Z, hex:00aabb, true, null, [2, 3, 4], { 1, 2, 1, 4}, {"a": "abc", "b": { "x": 12}}) <- true trusting authority, ${otherKeyPair.getPublicKey()}`;
  let facts2 = auth.queryWithLimits(r2, {
    max_time_micro: 100000,
  });
  t.equal(facts2.length, 1, "correct number of query results");
  console.log(facts2[0].terms());
  // fact terms can be destructured
  const [num, str, date, bytes, boolean, nul, array, set, map] =
    facts2[0].terms();
  t.equal(num, 1);
  t.equal(str, "a");
  // why is the hour shifted by 2 hours?
  t.equal(date.toISOString(), "2024-04-28T16:31:06.000Z");
  t.equal(bytes[0], 0);
  t.equal(bytes[1], 170);
  t.equal(bytes[2], 187);
  t.equal(boolean, true);
  t.equal(nul, null);
  t.equal(array[0], 2);
  t.equal(array[1], 3);
  t.equal(array[2], 4);
  t.ok(set.has(1));
  t.ok(set.has(2));
  t.ok(set.has(4));
  t.equal(map.get("a"), "abc");
  t.equal(map.get("b").get("x"), 12);

  t.equal(
    facts2[0].toString(),
    `test(1, "a", 2024-04-28T16:31:06Z, hex:00aabb, true, null, [2, 3, 4], {1, 2, 4}, {"a": "abc", "b": {"x": 12}})`,
    "correct query result"
  );

  t.end();
});

test("parameter injection", function (t) {
  t.equal(fact`fact(${1234})`.toString(), `fact(1234)`, "number");
  t.equal(fact`fact(${"1234"})`.toString(), `fact("1234")`, "string");
  t.equal(fact`fact(${true})`.toString(), `fact(true)`, "boolean");
  t.equal(
    fact`fact(${new Date("2023-03-28T14:31:06Z")})`.toString(),
    `fact(2023-03-28T14:31:06Z)`,
    "date"
  );
  t.equal(
    fact`fact(${["a", 12, true]})`.toString(),
    `fact(["a", 12, true])`,
    "array"
  );
  t.equal(
    fact`fact(${new Set(["a", 12, true])})`.toString(),
    `fact({12, "a", true})`,
    "set"
  );

  t.equal(
    fact`fact(${new Map([
      ["a", 12],
      ["b", true],
    ])})`.toString(),
    `fact({"a": 12, "b": true})`,
    "map"
  );

  let bytes = new Uint8Array(Buffer.from([0, 170, 187]));
  t.equal(fact`fact(${bytes})`.toString(), `fact(hex:00aabb)`, "byte array");
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
    fact(${new Set(["a", 12, true, new Date("2023-03-28T14:31:06Z")])});
    fact(${bytes});
    check if true trusting authority, ${pubkey};`.toString(),
    `fact(1234);
fact("1234");
fact(true);
fact(2023-03-28T14:31:06Z);
fact(["a", 12, true, 2023-03-28T14:31:06Z]);
fact({12, "a", 2023-03-28T14:31:06Z, true});
fact(hex:00aabb);
check if true trusting authority, ed25519/41e77e842e5c952a29233992dc8ebbedd2d83291a89bb0eec34457e723a69526;
`,
    "complete block"
  );
  t.end();
});

test("third-party blocks", function (t) {
  let pk = PrivateKey.fromString(
    "ed25519/473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97"
  );
  let root = KeyPair.fromPrivateKey(pk);

  let thirdPartyPk = PrivateKey.fromString(
    "ed25519/39c657dbd3f68b09bc8e5fd9887c7cb47a91d1d3883ffbc495ca790552398a92"
  );
  let thirdPartyRoot = KeyPair.fromPrivateKey(thirdPartyPk);

  let id = "1234";
  let biscuitBuilder = biscuit`user(${id});`;

  for (let right of ["read", "write"]) {
    biscuitBuilder.addFact(fact`right(${right})`);
  }

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
  let serializedToken = token.toBase64();
  console.log(serializedToken);

  let parsedToken = Biscuit.fromBase64(serializedToken, root.getPublicKey());
  let auth = authorizer`allow if user(${id})`.buildAuthenticated(parsedToken);

  let policy = auth.authorize();
  t.equal(policy, 0, "authorization suceeded");

  let r1 = rule`g($group) <- group($group) trusting ${thirdPartyRoot.getPublicKey()}`;
  let facts = auth.queryWithLimits(r1, {
    max_time_micro: 100000,
  });
  t.equal(facts.length, 1, "correct number of query results");
  t.equal(facts[0].toString(), `g("admin")`, "correct query result");

  let r2 = rule`g($group) <- group($group) trusting authority`;
  t.equal(auth.query(r2).length, 0, "correct number of query results");
  t.end();
});
