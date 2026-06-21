export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

function pathChild(path, key) {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)
    ? `${path}.${key}`
    : `${path}[${JSON.stringify(key)}]`;
}

export function validateCanonicalValue(value, path = "$", seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(`${path}: number must be an integer within the JS safe range`);
    }
    return;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new TypeError(`${path}: cyclic values are forbidden`);
    seen.add(value);
    value.forEach((item, index) => validateCanonicalValue(item, `${path}[${index}]`, seen));
    seen.delete(value);
    return;
  }
  if (typeof value === "object" && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    if (seen.has(value)) throw new TypeError(`${path}: cyclic values are forbidden`);
    seen.add(value);
    for (const [key, item] of Object.entries(value)) {
      if (!/^[\x00-\x7f]*$/.test(key)) {
        throw new TypeError(`${path}: object keys must be ASCII strings`);
      }
      validateCanonicalValue(item, pathChild(path, key), seen);
    }
    seen.delete(value);
    return;
  }
  throw new TypeError(`${path}: unsupported canonical JSON value`);
}

function quoteAscii(value) {
  let output = '"';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    switch (code) {
      case 0x08: output += "\\b"; break;
      case 0x09: output += "\\t"; break;
      case 0x0a: output += "\\n"; break;
      case 0x0c: output += "\\f"; break;
      case 0x0d: output += "\\r"; break;
      case 0x22: output += '\\"'; break;
      case 0x5c: output += "\\\\"; break;
      default:
        if (code < 0x20 || code > 0x7e) {
          output += `\\u${code.toString(16).padStart(4, "0")}`;
        } else {
          output += String.fromCharCode(code);
        }
    }
  }
  return `${output}"`;
}

function encode(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return quoteAscii(value);
  if (typeof value === "number") return Object.is(value, -0) ? "0" : String(value);
  if (Array.isArray(value)) return `[${value.map(encode).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${quoteAscii(key)}:${encode(value[key])}`).join(",")}}`;
}

export function canonicalJson(value) {
  validateCanonicalValue(value);
  return Buffer.from(encode(value), "ascii");
}

export function parseJsonStrict(text) {
  if (typeof text !== "string") throw new TypeError("JSON input must be a string");
  let offset = 0;
  const whitespace = /[\u0009\u000a\u000d\u0020]/;

  const skip = () => {
    while (offset < text.length && whitespace.test(text[offset])) offset += 1;
  };
  const parseString = () => {
    if (text[offset] !== '"') throw new SyntaxError(`expected string at offset ${offset}`);
    const start = offset++;
    let escaped = false;
    while (offset < text.length) {
      const char = text[offset++];
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === '"') {
        return JSON.parse(text.slice(start, offset));
      }
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const parseValue = () => {
    skip();
    const char = text[offset];
    if (char === '"') return parseString();
    if (char === "{") {
      offset += 1;
      const result = Object.create(null);
      const keys = new Set();
      skip();
      if (text[offset] === "}") { offset += 1; return result; }
      while (true) {
        skip();
        const key = parseString();
        if (keys.has(key)) throw new SyntaxError(`duplicate object key ${JSON.stringify(key)}`);
        keys.add(key);
        skip();
        if (text[offset++] !== ":") throw new SyntaxError(`expected colon at offset ${offset - 1}`);
        result[key] = parseValue();
        skip();
        const delimiter = text[offset++];
        if (delimiter === "}") return result;
        if (delimiter !== ",") throw new SyntaxError(`expected comma at offset ${offset - 1}`);
      }
    }
    if (char === "[") {
      offset += 1;
      const result = [];
      skip();
      if (text[offset] === "]") { offset += 1; return result; }
      while (true) {
        result.push(parseValue());
        skip();
        const delimiter = text[offset++];
        if (delimiter === "]") return result;
        if (delimiter !== ",") throw new SyntaxError(`expected comma at offset ${offset - 1}`);
      }
    }
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(literal, offset)) { offset += literal.length; return value; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(offset));
    if (!match) throw new SyntaxError(`invalid JSON value at offset ${offset}`);
    offset += match[0].length;
    if (/[.eE]/.test(match[0])) throw new TypeError("floats are forbidden by the Canon");
    const number = Number(match[0]);
    if (!Number.isSafeInteger(number)) throw new TypeError("integer outside the JS safe range");
    return number;
  };

  const value = parseValue();
  skip();
  if (offset !== text.length) throw new SyntaxError(`trailing JSON data at offset ${offset}`);
  validateCanonicalValue(value);
  return value;
}
