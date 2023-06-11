import { Claims, JwtClient } from '../index';
import test from 'ava';
import * as jose from 'jose';

const secret = 'testsecretkeycanbeexposed';
const normalExpiresIn = 10000;
const secretEnc = new TextEncoder().encode(secret);
const client = new JwtClient(secret);

const testPayload = { user: 'test@carbonteq.dev' };

test('should create a valid token from payload', async (t) => {
  const token = client.sign(testPayload, normalExpiresIn);
  const joseVerifyRes = await jose.jwtVerify(token, secretEnc);

  t.deepEqual(joseVerifyRes.payload?.data, testPayload);
});

test('should create a valid token from claims', async (t) => {
  const claims = new Claims(testPayload, normalExpiresIn);
  const token = client.signClaims(claims);
  const joseVerifyRes = await jose.jwtVerify(token, secretEnc);

  t.deepEqual(joseVerifyRes.payload?.data, testPayload);
});

test('created token should be valid', (t) => {
  const token = client.sign(testPayload, normalExpiresIn);

  t.deepEqual(client.verify(token).data, testPayload);
});

test('created (claims) token should be valid', (t) => {
  const claims = new Claims(testPayload, normalExpiresIn);
  const token = client.signClaims(claims);

  t.deepEqual(client.verify(token).data, testPayload);
});

test('verifying after exp should return false', (t) => {
  const claims = new Claims(testPayload, 2);
  claims.exp = 10; // In the past
  const token = client.signClaims(claims);

  t.throws(() => client.verify(token));
});

test('decode output should give the correct payload data', (t) => {
  const token = client.sign(testPayload, normalExpiresIn);
  const decoded = client.decode(token);

  t.deepEqual(decoded.data, testPayload);
});

test('decode output should give the correct payload data for claims', (t) => {
  const claims = new Claims(testPayload, normalExpiresIn);
  const token = client.signClaims(claims);
  const decoded = client.decode(token);

  t.deepEqual(decoded.data, testPayload);
});

test('decoding after exp should return payload', (t) => {
  const claims = new Claims(testPayload, 2);
  claims.exp = 10; // In the past
  const token = client.signClaims(claims);

  t.deepEqual(client.decode(token).data, testPayload);
});
