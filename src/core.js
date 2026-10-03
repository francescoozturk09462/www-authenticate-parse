/**
 * WWW-Authenticate header parser.
 *
 * Grammar reference (RFC 7235 §4.1):
 *   WWW-Authenticate = 1#challenge
 *   challenge        = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
 *   auth-scheme      = token
 *   auth-param       = token BWS "=" BWS ( token / quoted-string )
 *
 * token68 is a limited charset alternative to a full parameter list used by
 * schemes like Bearer (e.g. `Bearer abc123`). We keep it as the special
 * parameter key "token68" so callers can distinguish it from named params.
 *
 * Design decisions, stated plainly:
 *  - Parameters are returned as a Map<string,string>. Quoted-string escapes
 *    are decoded per RFC 7230 §3.2.6. Unquoted tokens are stored verbatim.
 *  - Parameter keys are compared case-insensitively per RFC 7235 (auth-param
 *    names are tokens; schemes define `realm` which is case-insensitive).
 *    Duplicate keys within one challenge: last-wins, matching typical header
 *    merge semantics. We do not error.
 *  - Multiple challenges separated by commas at the top level are supported.
 *    The tricky part is that commas also appear inside quoted-strings, so we
 *    can't split on commas naively — we track quote state while scanning.
 *  - We do NOT attempt to validate auth-scheme tokens beyond the grammar's
 *    charset. Unknown schemes are still returned; the caller decides policy.
 *  - realm is surfaced as a top-level field for convenience, pulled from the
 *    case-insensitive "realm" param. It is also present in the params map.
 */

/**
 * A single authentication challenge.
 */
export class Challenge {
  /**
   * @param {string} scheme        Auth scheme token, e.g. "Basic", "Bearer".
   *                               Preserved as-is (case retained).
   * @param {string|null} realm    Value of the realm param if present (decoded),
   *                               or null if the challenge had no realm.
   * @param {Map<string, string>} params  Parameter map with case-insensitive
   *                               lookup semantics preserved (original key
   *                               casing is kept as the stored key, but `get`
   *                               on the returned map should be done via the
   *                               helper `param()` to be case-insensitive).
   * @param {string|null} token68  The token68 value if the challenge used that
   *                               form instead of auth-param list, else null.
   */
  constructor(scheme, realm, params, token68) {
    this.scheme = scheme;
    this.realm = realm;
    this.params = params;
    this.token68 = token68;
  }

  /**
   * Case-insensitive parameter lookup. Auth-param names are tokens and the
   * `realm` key is conventionally matched case-insensitively; we extend that
   * to all params so callers don't have to guess casing.
   * @param {string} name
   * @returns {string|undefined}
   */
  param(name) {
    const lower = name.toLowerCase();
    for (const [k, v] of this.params) {
      if (k.toLowerCase() === lower) return v;
    }
    return undefined;
  }
}

// RFC 7230 §3.2.6 token charset. We also allow the scheme token to be a
// valid token; schemes are registered case-insensitively but we keep casing.
const TOKEN_CHARS = new Set(
  "!#$%&'*+-.^_`|~".split('').concat(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split(''),
    'abcdefghijklmnopqrstuvwxyz'.split(''),
    '0123456789'.split('')
  )
);

// token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) "="*
const TOKEN68_CHARS = new Set(
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/'.split('')
);

/**
 * Parse a WWW-Authenticate header value into one or more Challenge objects.
 *
 * @param {string} header
 * @returns {Challenge[]}  At least one challenge if the input is non-empty
 *                         and begins with a valid scheme token; an empty
 *                         array if the input is empty or whitespace-only.
 * @throws {TypeError} if `header` is not a string.
 */
export function parseWWWAuthenticate(header) {
  if (typeof header !== 'string') {
    throw new TypeError(`header must be a string, got ${typeof header}`);
  }
  const trimmed = header.trim();
  if (trimmed === '') return [];

  const challenges = splitChallenges(trimmed);
  const out = [];
  for (const raw of challenges) {
    const ch = parseOneChallenge(raw);
    if (ch) out.push(ch);
  }
  return out;
}

/**
 * Split the header into raw challenge strings. Commas separate challenges
 * ONLY when not inside a quoted-string. Whitespace-only fragments between
 * commas are dropped (the grammar's 1#list allows empty elements after
 * commas in some readings; we treat them as noise and skip them so that a
 * trailing comma doesn't create a phantom empty challenge).
 *
 * @param {string} s
 * @returns {string[]}
 */
function splitChallenges(s) {
  const parts = [];
  let buf = '';
  let inQuotes = false;
  let escape = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQuotes) {
      buf += c;
      if (escape) {
        escape = false;
      } else if (c === '\\') {
        escape = true;
      } else if (c === '"') {
        inQuotes = false;
      }
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      buf += c;
      continue;
    }
    if (c === ',') {
      if (buf.trim() !== '') parts.push(buf.trim());
      buf = '';
      continue;
    }
    buf += c;
  }
  if (buf.trim() !== '') parts.push(buf.trim());
  return parts;
}

/**
 * Parse a single challenge string of the form:
 *   scheme
 *   scheme token68
 *   scheme key=value key="value" ...
 *
 * @param {string} s
 * @returns {Challenge|null}
 */
function parseOneChallenge(s) {
  const { token: scheme, rest } = readToken(s);
  if (!scheme) return null;

  const params = new Map();
  let realm = null;
  let token68 = null;

  const body = rest.trim();
  if (body === '') {
    return new Challenge(scheme, realm, params, token68);
  }

  // Decide: token68 or auth-param list.
  // token68 is detected when the first body token contains characters not
  // valid as the start of an auth-param (i.e. not a token followed by '='),
  // OR when it is followed by no '='. We look ahead: if we can read a token
  // and the char after is '=', it's an auth-param; otherwise treat as token68.
  const probe = readToken(body);
  const afterProbe = body.slice(probe.consumed).trimStart();
  const looksLikeParam = probe.token !== null && afterProbe.startsWith('=');

  if (!looksLikeParam) {
    // token68: consume the rest of the challenge up to end as a single value.
    // Per RFC 7235, token68 ends at a comma — but commas at the top level here
    // were already removed by splitChallenges, so the whole body is token68.
    // We still validate the charset loosely; trailing '=' is allowed.
    token68 = body;
    return new Challenge(scheme, realm, params, token68);
  }

  // Auth-param list.
  let cursor = 0;
  while (cursor < body.length) {
    // skip whitespace and stray commas (commas between params are allowed by
    // the #auth-param production and are treated as separators here).
    while (cursor < body.length && (body[cursor] === ' ' || body[cursor] === '\t' || body[cursor] === ',')) {
      cursor++;
    }
    if (cursor >= body.length) break;

    const { token: key, consumed: kConsumed } = readToken(body.slice(cursor));
    if (!key) break; // malformed; stop.
    cursor += kConsumed;
    while (cursor < body.length && (body[cursor] === ' ' || body[cursor] === '\t')) cursor++;
    if (cursor >= body.length || body[cursor] !== '=') break;
    cursor++; // consume '='
    while (cursor < body.length && (body[cursor] === ' ' || body[cursor] === '\t')) cursor++;

    const { value, consumed } = readParamValue(body.slice(cursor));
    cursor += consumed;

    // last-wins on duplicate keys (case-sensitive storage; lookup via param()
    // is case-insensitive).
    params.set(key, value);
    if (key.toLowerCase() === 'realm' && realm === null) {
      realm = value;
    } else if (key.toLowerCase() === 'realm') {
      realm = value;
    }
  }

  return new Challenge(scheme, realm, params, token68);
}

/**
 * Read a token from the start of `s`. Stops at the first non-token char.
 * @returns {{token: string|null, consumed: number, rest: string}}
 */
function readToken(s) {
  let i = 0;
  while (i < s.length && TOKEN_CHARS.has(s[i])) i++;
  if (i === 0) return { token: null, consumed: 0, rest: s };
  return { token: s.slice(0, i), consumed: i, rest: s.slice(i) };
}

/**
 * Read an auth-param value: either a quoted-string (with backslash escapes
 * decoded per RFC 7230 §3.2.6) or a bare token. Returns the decoded value and
 * how many source characters were consumed.
 *
 * @param {string} s
 * @returns {{value: string, consumed: number}}
 */
function readParamValue(s) {
  if (s[0] === '"') {
    // Quoted-string. Decode escapes: \X -> X.
    let out = '';
    let i = 1; // skip opening quote
    while (i < s.length) {
      const c = s[i];
      if (c === '\\' && i + 1 < s.length) {
        out += s[i + 1];
        i += 2;
        continue;
      }
      if (c === '"') {
        i++; // consume closing quote
        return { value: out, consumed: i };
      }
      out += c;
      i++;
    }
    // Unterminated quoted-string: be lenient, take what we have.
    return { value: out, consumed: i };
  }
  // Bare token value.
  const { token, consumed } = readToken(s);
  return { value: token ?? '', consumed };
}
