// cjs module used to import performance.now() in wasm to measure execution time
// this must replace for node the file distributed by biscuit-rust, because that one
// is an ESM
function performance_now() {
  return performance.now();
}

module.exports.performance_now = performance_now;
