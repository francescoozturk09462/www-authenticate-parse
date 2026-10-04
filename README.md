# WWW Authenticate Parse

Parses a `WWW-Authenticate` HTTP header value into one or more challenges, each with its scheme, realm, and a parameter map.

```js
import { parseWWWAuthenticate } from 'www-authenticate-parse';

const challenges = parseWWWAuthenticate('Basic realm="WallyWorld", Bearer mF_9.B5f-4.1Zq');
for (const c of challenges) {
  console.log(c.scheme);   // "Basic", then "Bearer"
  console.log(c.realm);    // "WallyWorld", then null
  console.log(c.param('qop'));   // case-insensitive lookup
  console.log(c.token68);  // null, then "mF_9.B5f-4.1Zq"
}
```

Exports:
- `parseWWWAuthenticate(header: string): Challenge[]`
- `class Challenge { scheme: string; realm: string|null; params: Map<string,string>; token68: string|null; param(name: string): string|undefined }`

## Why

Parsing `WWW-Authenticate` by splitting on commas breaks the moment a `realm` value contains a comma inside a quoted string — which is legal and common. This library tracks quote state while scanning so it only splits between challenges, not inside them. That is the whole reason it exists; everything else is straightforward token handling.

The trade-off: we do not validate scheme names against an IANA registry, and we do not enforce that a challenge has exactly one of `token68` or an auth-param list — we detect which form is in use by looking ahead for a `=` after the first body token. This is permissive but matches what real servers send.

## Edge you will hit

Parameter keys are stored with their original casing, but auth-param names are tokens and `realm` is matched case-insensitively by convention. Use the `param()` method rather than `params.get()` directly if you want case-insensitive lookup. Duplicate keys within a single challenge keep the last value (last-wins), matching typical HTTP header merge semantics; we do not error.
