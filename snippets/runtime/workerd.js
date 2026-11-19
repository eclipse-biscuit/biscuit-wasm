import wasmModule from "./biscuit_bg.wasm";
import { initSync } from "./init.js";

export * from "./biscuit_bg.js";

initSync(wasmModule);
