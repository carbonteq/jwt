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

suite
  .add('jsonwebtoken#sign', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      jwt.sign(payload, secret);
      deferred.resolve();
    },
  })
  .add('jose#sign', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      joseSign(payload).then(() => deferred.resolve());
      // const s = new jose.SignJWT(payload);
      // s.setProtectedHeader({ alg: "HS256" }).sign(encodedKey).then(defer);
    },
  })
  .add('fastjwt#sign', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      const signer = fastJwt.createSigner({ key: secret });
      signer(payload);
      deferred.resolve();
    },
  })
  .add('@carbonteq/jwt#sign', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      client.sign(payload, 1000);
      deferred.resolve();
    },
  })
  .add('@carbonteq/jwt#signClaims', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      const claims = new Claims(payload, 1000);
      client.signClaims(claims);
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
