import express from "express";
import {
  biscuit,
  authorizer,
  KeyPair,
  middleware,
  PrivateKey,
} from "@biscuit-auth/biscuit-wasm";
import { readdir } from "node:fs/promises";
import path from "node:path";

const app = express();
const port = 3000;

const pk = "510fa4152b316a29c16e9459553e34abe891f006175bd61b7daca8b19f14ab90";
const keypair = KeyPair.fromPrivateKey(PrivateKey.fromString(pk));
const p = middleware({
  publicKey: keypair.getPublicKey(),
  priorityAuthorizer: (req) =>
    authorizer`allow if ${req.headers.prio ?? ""} == "true";`,
  fallbackAuthorizer: (req) =>
    authorizer`allow if ${req.headers.fall ?? ""} == "true";`,
});

app.get(
  "/protected/:dog",
  p((req) => authorizer`allow if scope(${req.params.dog}, "read");`),
  (req, res) => {
    if (req.params.dog === "puna") {
      readdir("./assets/puna")
        .then((files) => {
          const picName = files[Math.floor(Math.random() * files.length)];
          res.sendFile(`${picName}`, {
            root: path.resolve("assets/puna"),
          });
        })
        .catch((e) => {
          console.error(e);
          res.send(`${req.params.dog}!`);
        });
    } else {
      res.send(`${req.params.dog}!`);
    }
  }
);

app.listen(port, () => {
  const b = biscuit`
    scope("puna", "read");
  `.build(keypair.getPrivateKey());
  console.log("This token will grant you read access to /protected/puna");
  console.log(b.toBase64());
});
