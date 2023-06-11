import { Claims, JwtClient } from '../index.js';
import bench from 'benchmark';
import chalk from 'chalk';
import fastJwt from 'fast-jwt';
import * as jose from 'jose';
import jwt from 'jsonwebtoken';

const suite = new bench.Suite('Sign token');

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
  .add(
    'jsonwebtoken',
    () => {
      jwt.sign(payload, secret);
    },
    { minSamples },
  )
  .add(
    'jose',
    async (deferred) => {
      await joseSign(payload);
      deferred.resolve();
      // const s = new jose.SignJWT(payload);
      // s.setProtectedHeader({ alg: "HS256" }).sign(encodedKey).then(defer);
    },
    { defer: true, minSamples },
  )
  .add(
    'fast-jwt',
    () => {
      const signer = fastJwt.createSigner({ key: secret });
      signer(payload);
    },
    { minSamples },
  )
  .add(
    '@carbonteq/jwt',
    () => {
      client.sign(payload, 1000);
    },
    { minSamples },
  )
  .add(
    '@carbonteq/jwt#signClaims',
    () => {
      const claims = new Claims(payload, 1000);
      client.signClaims(claims);
    },
    { minSamples },
  )
  .on('cycle', (e) => {
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
