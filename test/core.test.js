import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseWWWAuthenticate, Challenge } from '../src/index.js';

test('empty string yields no challenges', () => {
  assert.deepEqual(parseWWWAuthenticate(''), []);
});

test('whitespace-only string yields no challenges', () => {
  assert.deepEqual(parseWWWAuthenticate('   \t  '), []);
});

test('scheme only, no params', () => {
  const [c] = parseWWWAuthenticate('Basic');
  assert.equal(c.scheme, 'Basic');
  assert.equal(c.realm, null);
  assert.equal(c.token68, null);
  assert.equal(c.params.size, 0);
});

test('Basic with realm', () => {
  const [c] = parseWWWAuthenticate('Basic realm="WallyWorld"');
  assert.equal(c.scheme, 'Basic');
  assert.equal(c.realm, 'WallyWorld');
  assert.equal(c.params.get('realm'), 'WallyWorld');
});

test('unquoted param value is accepted', () => {
  const [c] = parseWWWAuthenticate('Custom foo=bar');
  assert.equal(c.param('foo'), 'bar');
});

test('param lookup is case-insensitive', () => {
  const [c] = parseWWWAuthenticate('Basic Realm="x"');
  assert.equal(c.realm, 'x');
  assert.equal(c.param('REALM'), 'x');
});

test('quoted-string escapes are decoded', () => {
  const [c] = parseWWWAuthenticate('Basic realm="a\\"b, c"');
  assert.equal(c.realm, 'a"b, c');
});

test('comma inside quoted-string does not split challenges', () => {
  const [c] = parseWWWAuthenticate('Basic realm="a, b", Bearer token');
  assert.equal(c.scheme, 'Basic');
  assert.equal(c.realm, 'a, b');
});

test('multiple challenges are split on top-level commas', () => {
  const res = parseWWWAuthenticate('Basic realm="A", Bearer xyz');
  assert.equal(res.length, 2);
  assert.equal(res[0].scheme, 'Basic');
  assert.equal(res[0].realm, 'A');
  assert.equal(res[1].scheme, 'Bearer');
  assert.equal(res[1].token68, 'xyz');
});

test('Bearer with token68 value', () => {
  const [c] = parseWWWAuthenticate('Bearer mF_9.B5f-4.1Zq');
  assert.equal(c.scheme, 'Bearer');
  assert.equal(c.token68, 'mF_9.B5f-4.1Zq');
  assert.equal(c.params.size, 0);
});

test('trailing comma does not create phantom empty challenge', () => {
  const res = parseWWWAuthenticate('Basic realm="A",');
  assert.equal(res.length, 1);
  assert.equal(res[0].realm, 'A');
});

test('duplicate param keys: last-wins', () => {
  const [c] = parseWWWAuthenticate('Custom k="1" k="2"');
  assert.equal(c.param('k'), '2');
});

test('multiple auth-params on one challenge', () => {
  const [c] = parseWWWAuthenticate('Digest realm="test" qop="auth" nonce="abc"');
  assert.equal(c.scheme, 'Digest');
  assert.equal(c.realm, 'test');
  assert.equal(c.param('qop'), 'auth');
  assert.equal(c.param('nonce'), 'abc');
});

test('Challenge is an exported class', () => {
  assert.ok(typeof Challenge === 'function');
  const ch = new Challenge('Basic', null, new Map(), null);
  assert.equal(ch.scheme, 'Basic');
});

test('non-string input throws TypeError', () => {
  assert.throws(() => parseWWWAuthenticate(123), TypeError);
});

test('param() returns undefined for missing key', () => {
  const [c] = parseWWWAuthenticate('Basic realm="x"');
  assert.equal(c.param('missing'), undefined);
});
