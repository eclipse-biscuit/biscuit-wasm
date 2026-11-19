import * as bg from "./biscuit_bg.js";

const wasmImports = {};
for (const [key, value] of Object.entries(bg)) {
  if (key.startsWith("__wbg_") || key.startsWith("__wbindgen_")) {
    wasmImports[key] = value;
  }
}

const snippetExports = {
  performance_now: () => globalThis.performance.now(),
};
const snippetModules = __SNIPPET_MODULES__;

let initialized = false;

function toWasmModule(moduleOrBytes) {
  if (moduleOrBytes instanceof WebAssembly.Module) {
    return moduleOrBytes;
  }

  return new WebAssembly.Module(moduleOrBytes);
}

export function initSync(moduleOrBytes) {
  if (initialized) {
    return;
  }

  const imports = {
    "./biscuit_bg.js": wasmImports,
  };
  for (const path of snippetModules) {
    imports[path] = snippetExports;
  }

  const instance = new WebAssembly.Instance(
    toWasmModule(moduleOrBytes),
    imports
  );
  bg.__wbg_set_wasm(instance.exports);
  instance.exports.__wbindgen_start();
  initialized = true;
}
