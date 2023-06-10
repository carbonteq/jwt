import bench from 'benchmark';
import jwt from 'jsonwebtoken';
import fastJwt from 'fast-jwt';
import * as jose from 'jose';
import { Claims, JwtClient } from '../index.js';

const suite = new bench.Suite();

const secret = 'somelongsecretasdbnakwfbjawf';
const minSamples = 100;

const encodedKey = new TextEncoder().encode(secret);
const payload = { userId: 'abc123' };

const client = new JwtClient(secret);

const joseSign = async (payload) => {
  const s = new jose.SignJWT(payload);
  return s.setProtectedHeader({ alg: 'HS256' }).sign(encodedKey);
  // const key = jose.JWK.asKey(secret);
  // return await jose.JWT.sign(payload, key);
};

const joseSigned = await joseSign(payload);
const jwtSigned = jwt.sign(payload, secret);

const signer = fastJwt.createSigner({ key: secret });
const fastJwtDecode = fastJwt.createDecoder();
const fastJwtSigned = signer(payload);

const claims = new Claims(JSON.stringify(payload), 60000);
const fasterJwtSigned = client.signClaims(claims);

suite
  .add('jsonwebtoken#decode', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      jwt.decode(jwtSigned);
      deferred.resolve();
    },
  })
  .add('jose#decode', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      jose.decodeJwt(joseSigned);
      deferred.resolve();
    },
  })
  .add('fastjwt#decode', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      fastJwtDecode(fastJwtSigned);
      deferred.resolve();
    },
  })
  .add('@carbonteq/jwt#decode', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      client.decode(fasterJwtSigned);
      deferred.resolve();
    },
  })
  .on('cycle', (e) => {
    console.log(String(e.target));
  })
  .on('complete', function () {
    console.log('\nFastest is ' + this.filter('fastest').map('name'));
  })
  .run({ async: true });
