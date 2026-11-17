import {
  authorizer,
  biscuit,
  block,
  check,
  fact,
  rule,
  policy,
  Biscuit,
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
    "ed25519-private/76ac58cc933a3032d65e4d4faf99302fba381930486fd0ce1260654db25ca661";
  let pubStr =
    "ed25519/9d0b36243c1dd2ceec188b81e798c6a7f2954fc02bd4c3913eb1885a2999278b";
  let pk = PrivateKey.fromString(pkStr);
  t.equal(pk.toString(), pkStr, "private key roundtrip");
  t.equal(pk.getPublicKey().toString(), pubStr, "public key generation");
  t.end();
});

test("ECDSA keypair generation", function (t) {
  let kp = new PrivateKey(SignatureAlgorithm.Secp256r1);
  console.log(kp.getPublicKey().toString());
  t.ok(
    kp.getPublicKey().toString().startsWith("secp256r1/"),
    "public key prefix"
  );
  t.ok(kp.toString().startsWith("secp256r1-private/"), "private key prefix");

  let kp2 = new PrivateKey(SignatureAlgorithm.Ed25519);
  console.log(kp2.getPublicKey().toString());
  t.ok(
    kp2.getPublicKey().toString().startsWith("ed25519/"),
    "public key prefix"
  );
  t.ok(kp2.toString().startsWith("ed25519-private/"), "private key prefix");

  let kp3 = new PrivateKey();
  console.log(kp3.getPublicKey().toString());
  t.ok(
    kp3.getPublicKey().toString().startsWith("ed25519/"),
    "public key prefix"
  );
  t.ok(kp3.toString().startsWith("ed25519-private/"), "private key prefix");

  let id = "1234";
  let biscuitBuilder = biscuit`user(${id});`;

  biscuitBuilder.setRootKeyId(1234);
  let token = biscuitBuilder.build(kp).appendBlock(block`check if user($u)`);
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
    "ed25519-private/76ac58cc933a3032d65e4d4faf99302fba381930486fd0ce1260654db25ca661";
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
  builder.mergeBlock(block`check if true`);
  builder.merge(authorizer`deny if true`);

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
  let root = PrivateKey.fromString(
    "ed25519-private/473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97"
  );

  let id = "1234";
  let biscuitBuilder = biscuit`user(${id});`;

  for (let right of ["read", "write"]) {
    biscuitBuilder.addFact(fact`right(${right})`);
  }

  biscuitBuilder.setRootKeyId(1234);
  let token = biscuitBuilder
    .build(root) // biscuit token
    .appendBlock(block`check if user($u)`); // attenuated biscuit token
  let serializedToken = token.toBase64();

  let parsedToken = Biscuit.fromBase64WithProvider(
    serializedToken,
    function (key_id) {
      if (key_id === 1234) {
        console.log("key", root.getPublicKey().toString());
        return root.getPublicKey();
      }
      throw new Error("Unknown key id: " + key_id);
    }
  );
  let auth = authorizer`allow if user(${id})`.buildAuthenticated(parsedToken);

  let policy = auth.authorize();
  t.equal(policy, 0, "authorization suceeded");

  let otherKey = new PrivateKey();
  let r = rule`u($id) <- user($id), $id == ${id} trusting authority, ${otherKey.getPublicKey()}`;
  let facts = auth.queryWithLimits(r, {
    max_time_micro: 100000,
  });
  t.equal(facts.length, 1, "correct number of query results");
  t.equal(facts[0].toString(), `u("1234")`, "correct query result");

  let r2 = rule`test(1, "a", 2024-04-28T16:31:06Z, hex:00aabb, true, null, [2, 3, 4], { 1, 2, 1, 4}, {"a": "abc", "b": { "x": 12}}) <- true trusting authority, ${otherKey.getPublicKey()}`;
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

  // test with nested maps and arrays
  let r3 = rule`test({"a": "abc", "b": [{"x": 12}, {"y": "xyz"}, {"z": [{ "a": "b" }, {"a": "c"}]}]}) <- true`;
  let facts3 = auth.queryWithLimits(r3, {
    max_time_micro: 100000,
  });
  t.equal(
    facts3[0].toString(),
    `test({"a": "abc", "b": [{"x": 12}, {"y": "xyz"}, {"z": [{"a": "b"}, {"a": "c"}]}]})`,
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
  let root = PrivateKey.fromString(
    "ed25519-private/473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97"
  );

  let thirdPartyPk = PrivateKey.fromString(
    "ed25519-private/39c657dbd3f68b09bc8e5fd9887c7cb47a91d1d3883ffbc495ca790552398a92"
  );

  let id = "1234";
  let biscuitBuilder = biscuit`user(${id});`;

  for (let right of ["read", "write"]) {
    biscuitBuilder.addFact(fact`right(${right})`);
  }

  biscuitBuilder.addCheck(
    check`check if group("admin") trusting ${thirdPartyPk.getPublicKey()}`
  );

  let token = biscuitBuilder
    .build(root) // biscuit token
    .appendBlock(block`check if user($u)`); // attenuated biscuit token

  let thirdPartyRequest = token.getThirdPartyRequest();
  let thirdPartyBlock = thirdPartyRequest.createBlock(
    thirdPartyPk,
    block`group("admin");`
  );

  token = token.appendThirdPartyBlock(
    thirdPartyPk.getPublicKey(),
    thirdPartyBlock
  );
  let serializedToken = token.toBase64();
  console.log(serializedToken);

  let parsedToken = Biscuit.fromBase64(serializedToken, root.getPublicKey());
  let auth = authorizer`allow if user(${id})`.buildAuthenticated(parsedToken);

  let policy = auth.authorize();
  t.equal(policy, 0, "authorization suceeded");

  let r1 = rule`g($group) <- group($group) trusting ${thirdPartyPk.getPublicKey()}`;
  let facts = auth.queryWithLimits(r1, {
    max_time_micro: 100000,
  });
  t.equal(facts.length, 1, "correct number of query results");
  t.equal(facts[0].toString(), `g("admin")`, "correct query result");

  let r2 = rule`g($group) <- group($group) trusting authority`;
  t.equal(auth.query(r2).length, 0, "correct number of query results");
  t.end();
});

test("deserialization limits", function (t) {
  let root = new PrivateKey();
  let token = biscuit`user("1234"); right("read"); right("write");`
    .build(root)
    .appendBlock(block`check if user($u)`);
  let serializedToken = token.toBase64();
  let tokenBytes = token.toBytes();
  let provider = () => root.getPublicKey();

  let parsed = Biscuit.fromBase64WithLimits(
    serializedToken,
    root.getPublicKey(),
    {}
  );
  t.equal(parsed.countBlocks(), 2, "empty limits allow everything");

  let blockLimits = { max_blocks: 1 };
  let tooManyBlocks = {
    type: "format",
    value: { type: "token_limit", value: "too_many_blocks" },
  };
  t.throws(
    () =>
      Biscuit.fromBase64WithLimits(
        serializedToken,
        root.getPublicKey(),
        blockLimits
      ),
    (e) => t.deepEqual(e, tooManyBlocks) || true,
    "base64 token with too many blocks"
  );
  t.throws(
    () =>
      Biscuit.fromBytesWithLimits(tokenBytes, root.getPublicKey(), blockLimits),
    (e) => t.deepEqual(e, tooManyBlocks) || true,
    "token with too many blocks"
  );
  t.throws(
    () =>
      Biscuit.fromBase64WithProviderAndLimits(
        serializedToken,
        provider,
        blockLimits
      ),
    (e) => t.deepEqual(e, tooManyBlocks) || true,
    "base64 token with too many blocks, with provider"
  );
  t.throws(
    () =>
      Biscuit.fromBytesWithProviderAndLimits(tokenBytes, provider, blockLimits),
    (e) => t.deepEqual(e, tooManyBlocks) || true,
    "token with too many blocks, with provider"
  );

  t.throws(
    () =>
      Biscuit.fromBytesWithLimits(tokenBytes, root.getPublicKey(), {
        authority: { max_facts: 2 },
      }),
    (e) =>
      t.deepEqual(e, {
        type: "format",
        value: {
          type: "block_limit",
          value: { block_id: 0, limit: "too_many_facts" },
        },
      }) || true,
    "authority block with too many facts"
  );

  t.throws(
    () =>
      Biscuit.fromBytesWithLimits(tokenBytes, root.getPublicKey(), {
        attenuations: { allowed_check_kinds: ["all"] },
      }),
    (e) =>
      t.deepEqual(e, {
        type: "format",
        value: {
          type: "block_limit",
          value: { block_id: 1, limit: "check_kind_not_allowed" },
        },
      }) || true,
    "attenuation block with a disallowed check kind"
  );

  t.throws(
    () =>
      Biscuit.fromBytesWithLimits(tokenBytes, root.getPublicKey(), {
        allowed_internal_signing_algorithms: ["secp256r1"],
      }),
    "token signed with a disallowed algorithm"
  );

  t.throws(
    () =>
      Biscuit.fromBytesWithLimits(tokenBytes, root.getPublicKey(), {
        max_block: 1,
      }),
    "unknown limit field"
  );
  t.end();
});

test("authorizer run limits", function (t) {
  let root = new PrivateKey();
  let token = biscuit`user("1234");`.build(root);

  let builder = authorizer`
    data(1); data(2); data(3);
    other($x) <- data($x);
    allow if user($u);
  `;
  t.equal(
    builder.buildAuthenticated(token).authorize(),
    0,
    "default limits allow authorization"
  );

  builder = authorizer`
    data(1); data(2); data(3);
    other($x) <- data($x);
    allow if user($u);
  `;
  builder.setLimits({ max_facts: 5 });
  let auth = builder.buildAuthenticated(token);
  t.throws(
    () => auth.authorize(),
    (e) =>
      t.deepEqual(e, {
        type: "run_limit",
        value: { type: "too_many_facts" },
      }) || true,
    "authorize uses the builder limits"
  );
  t.end();
});

test("deserialization limits on block contents", function (t) {
  let root = new PrivateKey();
  let external = new PrivateKey();
  let token = biscuit`
    data({1, 2});
    map({"a": 1});
    check if data($d), $d.length() > 1;
    check if group("admin") trusting ${external.getPublicKey()};
  `.build(root);
  let tokenBytes = token.toBytes();

  let cases = [
    [{ allowed_term_types: ["integer", "string", "map"] }, "term_type_not_allowed"],
    [{ allowed_map_key_types: ["integer"] }, "map_key_type_not_allowed"],
    [{ allowed_unary_ops: ["negate"] }, "unary_operation_not_allowed"],
    [{ allowed_binary_ops: ["less_than"] }, "binary_operation_not_allowed"],
    [{ allowed_trusting_scopes: ["authority"] }, "trusted_scope_not_allowed"],
  ];
  for (let [authority, limit] of cases) {
    t.throws(
      () =>
        Biscuit.fromBytesWithLimits(tokenBytes, root.getPublicKey(), {
          authority,
        }),
      (e) =>
        t.deepEqual(e, {
          type: "format",
          value: { type: "block_limit", value: { block_id: 0, limit } },
        }) || true,
      limit
    );
  }

  let parsed = Biscuit.fromBytesWithLimits(tokenBytes, root.getPublicKey(), {
    authority: {
      allowed_term_types: ["integer", "string", "set", "map"],
      allowed_map_key_types: ["string"],
      allowed_unary_ops: ["length"],
      allowed_binary_ops: ["greater_than"],
      allowed_trusting_scopes: [{ public_key: "ed25519" }],
    },
  });
  t.equal(parsed.countBlocks(), 1, "token respecting the limits");
  t.end();
});
