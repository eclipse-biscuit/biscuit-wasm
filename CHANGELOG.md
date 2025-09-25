# `0.6.0-beta1`

- Bump biscuit-auth to `6.0.0` (#51, #54) (Geoffroy Couprie, Tomáš Čarnecký)

# `0.5.0`

- Bump biscuit-auth to `5.0.0` (Clément Delafargue)

# `0.4.1`

- Bump biscuit-auth to `4.1.1` (#40) (Clément Delafargue)
- Add `.setRootKeyId()` to biscuit builder (#44) (louisjmorgan)
- Stricter `Authorization` header parsing in express middleware (#39) (Clément Delafargue)
- Documentation fixes (#38) (Clément Delafargue)

# `0.4.0`

- Bump biscuit-auth to `3.1.0` (#36) (Clément Delafargue)

# `0.4.0-beta3`

- Add `merge` and `mergeBlock` to `Authorizer` (#35) (Clément Delafargue)
- Add an express middleware for proctecting endpoints (#35) (Clément Delafargue)

# `0.4.0-beta2`

- Fix `appendThirdPartyBlock` (#34) (Clément Delafargue)
- Prevent parameter nullifying in the public API (#34) (Clément Delafargue)
- Improve TS definitions (#34) (Pierre Tondereau)

# `0.4.0-beta1`

- CI (#25, #30) (Pierre Tondereau, Clément Delafargue)
- `fact`, `rule`, `check`, `policy` tagged templates (#18, #24, #26) (Clément Delafargue)
- Better `toString` implementations (#27) (Clément Delafargue)
- Support for authorization limits (#28) (Clément Delafargue)
- Revocation ids are now hex-encoded (#29) (Clément Delafargue)
- Support for injecting the full range of datalog term types (#30) (Clément Delafargue)
- Add typescript definitions for tagged templates (#25) (Clément Delafargue)

# `0.4.0-alpha3`

- `block` tagged template (#18) (Clément Delafargue)

# `0.4.0-alpha2`

- `biscuit`, `authorizer` tagged templates (#18) (Clément Delafargue)

# `0.4.0-alpha1`

- allow creating a `KeyPair` from a `PrivateKey` (#1) (kanru)
- esm support (#6) (Geoffroy Couprie)
- support for biscuit 3.0 (#3) (Geoffroy Couprie)
- more idiomatic JS naming (#7) (flyboarder)
- make `BiscuitBuilder` constructor public & clippy fixes (#10) (Pierre Tondereau)
- API cleanup (#9) (Geoffroy Couprie)
- Support for authorizer queries (#12) (Geoffroy Couprie)

# `0.3.0`
