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

test('created token should be valid', (t) => {
  const token = client.sign(testPayload, normalExpiresIn);

  t.deepEqual(client.verify(token).data, testPayload);
});

test('verifying after exp should throw error', (t) => {
  const claims = new Claims(testPayload, 1);
  claims.exp = 10;

  const token = client.signClaims(claims);
  t.throws(() => {
    client.verify(token);
  });
});
