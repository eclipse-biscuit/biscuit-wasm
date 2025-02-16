import {
  Biscuit,
  Authorizer,
  Rule,
  Fact,
  Check,
  Policy,
} from "./biscuit_bg.js";

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function prepareTerm(value) {
  if (value instanceof Date) {
    return { date: value.toISOString() };
  } else if (value instanceof Uint8Array) {
    return { bytes: bytesToHex(value) };
  } else if (Array.isArray(value)) {
    return value.map(prepareTerm);
  } else if (typeof value.toDatalogParameter === "function") {
    return value.toDatalogParameter();
  } else {
    return value;
  }
}

function tagged(builder) {
  return (strings, ...values) => {
    let code = "";
    for (let i = 0; i < strings.length; i++) {
      code += strings[i];
      if (i < values.length) {
        code += `{param_${i}}`;
      }
    }

    const termParameters = Object.fromEntries(
      values.map((v, i) => {
        return [`param_${i}`, prepareTerm(v)];
      })
    );

    const isKeyParam = (v) => {
      return (
        (typeof v === "string" && v.startsWith("ed25519/")) ||
        v.toDatalogParameter
      );
    };

    const keyParameters = Object.fromEntries(
      values
        .map((v, i) => [i, v])
        .filter(([i, v]) => isKeyParam(v))
        .map(([i, v]) => {
          return [`param_${i}`, prepareTerm(v)];
        })
    );

    console.log(code, termParameters, keyParameters);
    return builder.addCodeWithParameters(code, termParameters, keyParameters);
  };
}

export function biscuit(strings, ...values) {
  const builder = Biscuit.builder();
  return tagged(builder)(strings, ...values);
}

export function block(strings, ...values) {
  const builder = Biscuit.block_builder();
  return tagged(builder)(strings, ...values);
}

export function authorizer(strings, ...values) {
  const builder = new Authorizer();
  return tagged(builder)(strings, ...values);
}

export function fact(strings, ...values) {
  let code = "";
  for (let i = 0; i < strings.length; i++) {
    code += strings[i];
    if (i < values.length) {
      code += `{param_${i}}`;
    }
  }

  const params = new Map(
    values.map((v, i) => {
      return [`param_${i}`, prepareTerm(v)];
    })
  );

  const f = Fact.fromString(code);
  const unboundParams = f.unboundParameters();

  for (let p of unboundParams) {
    f.set(p, params.get(p));
  }

  return f;
}

export function rule(strings, ...values) {
  let code = "";
  for (let i = 0; i < strings.length; i++) {
    code += strings[i];
    if (i < values.length) {
      code += `{param_${i}}`;
    }
  }

  const params = new Map(
    values.map((v, i) => {
      return [`param_${i}`, prepareTerm(v)];
    })
  );

  const r = Rule.fromString(code);
  const unboundParams = r.unboundParameters();
  const unboundScopeParams = r.unboundScopeParameters();

  for (let p of unboundParams) {
    r.set(p, params.get(p));
  }

  for (let p of unboundScopeParams) {
    r.setScope(p, params.get(p));
  }

  return r;
}

export function check(strings, ...values) {
  let code = "";
  for (let i = 0; i < strings.length; i++) {
    code += strings[i];
    if (i < values.length) {
      code += `{param_${i}}`;
    }
  }

  const params = new Map(
    values.map((v, i) => {
      return [`param_${i}`, prepareTerm(v)];
    })
  );

  const c = Check.fromString(code);
  const unboundParams = c.unboundParameters();
  const unboundScopeParams = c.unboundScopeParameters();

  for (let p of unboundParams) {
    c.set(p, params.get(p));
  }

  for (let p of unboundScopeParams) {
    c.setScope(p, params.get(p));
  }

  return c;
}

export function policy(strings, ...values) {
  let code = "";
  for (let i = 0; i < strings.length; i++) {
    code += strings[i];
    if (i < values.length) {
      code += `{param_${i}}`;
    }
  }

  const params = new Map(
    values.map((v, i) => {
      return [`param_${i}`, prepareTerm(v)];
    })
  );

  const pol = Policy.fromString(code);
  const unboundParams = pol.unboundParameters();
  const unboundScopeParams = pol.unboundScopeParameters();

  for (let p of unboundParams) {
    pol.set(p, params.get(p));
  }

  for (let p of unboundScopeParams) {
    pol.setScope(p, params.get(p));
  }

  return pol;
}
