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
const expires_in = 60000;

const joseSign = async (payload) => {
  const s = new jose.SignJWT(payload);
  return s.setProtectedHeader({ alg: 'HS256' }).sign(encodedKey);
  // const key = jose.JWK.asKey(secret);
  // return await jose.JWT.sign(payload, key);
};

const joseSigned = await joseSign(payload);
const jwtSigned = jwt.sign(payload, secret);

const signer = fastJwt.createSigner({ key: secret });
const fastJwtVerify = fastJwt.createVerifier({ key: secret });
const fastJwtSigned = signer(payload);

const claims = new Claims(JSON.stringify(payload), expires_in);
const fasterJwtSigned = client.signClaims(claims);

suite
  .add('jsonwebtoken#verify', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      jwt.verify(jwtSigned, secret);
      deferred.resolve();
    },
  })
  .add('jose#verify', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      jose.jwtVerify(joseSigned, encodedKey).then(() => deferred.resolve());
    },
  })
  .add('fastjwt#verify', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      const verifyIt = fastJwt.createVerifier({ key: secret });
      verifyIt(fastJwtSigned);
      deferred.resolve();
    },
  })
  .add('fastjwt#verifyWithCache', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      fastJwtVerify(fastJwtSigned);
      deferred.resolve();
    },
  })
  .add('@carbonteq/jwt#verify', {
    defer: true,
    minSamples,
    fn: function (deferred) {
      client.verify(fasterJwtSigned);
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
