import test from 'ava';
import { JwtClient } from '../index';
import * as jose from 'jose';

const secret = 'testsecretkeycanbeexposed';
const secretEnc = new TextEncoder().encode(secret);
const client = new JwtClient(secret);

const testPayload = { user: 'test@carbonteq.dev' };
const testPayloadSer = JSON.stringify(testPayload);

test('should create a valid token from claims', async (t) => {
  const token = client.sign(testPayloadSer, 10000);
  const joseVerifyRes = await jose.jwtVerify(token, secretEnc);

  t.is(joseVerifyRes.payload?.data, testPayloadSer);
});

test('created token should be valid', (t) => {
  const token = client.sign(testPayloadSer, 10000);

  t.true(client.verify(token));
});

test('decode output should give the correct payload data', (t) => {
  const token = client.sign(testPayloadSer, 10000);
  const decoded = client.decode(token);

  t.is(decoded.data, testPayloadSer);
});
