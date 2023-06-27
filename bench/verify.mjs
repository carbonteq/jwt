import { JwtClient, JwtCacheClient } from '../index.js';
import bench from 'benchmark';
import chalk from 'chalk';
import fastJwt from 'fast-jwt';
import * as jose from 'jose';
import jwt from 'jsonwebtoken';

const suite = new bench.Suite('Verify Token');

const secret = 'somelongsecretasdbnakwfbjawf';
const minSamples = 100;

const encodedKey = new TextEncoder().encode(secret);
const payload = { userId: 'abc123' };

const expires_in = 60000;
const client = new JwtClient(secret);
const cacheClient = new JwtCacheClient(secret, expires_in, 2);

const joseSign = async (payload) => {
  const s = new jose.SignJWT(payload);
  return s.setProtectedHeader({ alg: 'HS256' }).sign(encodedKey);
  // const key = jose.JWK.asKey(secret);
  // return await jose.JWT.sign(payload, key);
};

const joseSigned = await joseSign(payload);
const jwtSigned = jwt.sign(payload, secret);

const signer = fastJwt.createSigner({ key: secret });
const fastJwtVerify = fastJwt.createVerifier({ key: secret, cache: false });
const fastJwtCacheVerify = fastJwt.createVerifier({
  key: secret,
  cache: true,
  cacheTTL: expires_in,
});
const fastJwtSigned = signer(payload);

const ctJwtSigned = client.sign(payload, expires_in);

suite
  .add(
    'jsonwebtoken',
    () => {
      jwt.verify(jwtSigned, secret);
    },
    { minSamples },
  )
  .add(
    'jose',
    async (deferred) => {
      await jose.jwtVerify(joseSigned, encodedKey);
      deferred.resolve();
    },
    { defer: true, minSamples },
  )
  .add(
    'fast-jwt',
    () => {
      fastJwtVerify(fastJwtSigned);
    },
    { minSamples },
  )
  .add(
    'fast-jwt#withCache',
    () => {
      fastJwtCacheVerify(fastJwtSigned);
    },
    { minSamples },
  )
  .add(
    '@carbonteq/jwt',
    () => {
      client.verify(ctJwtSigned);
    },
    { minSamples },
  )
  .add(
    '@carbonteq/jwt#withCache',
    () => {
      cacheClient.verify(ctJwtSigned);
    },
    { minSamples },
  )
  .on('cycle', function (e) {
    console.log(String(e.target));
  })
  .on('complete', function () {
    console.log(
      `\nSUITE <${this.name}>: Fastest is ${chalk.green(
        this.filter('fastest').map('name'),
      )}`,
    );
  })
  .run();
