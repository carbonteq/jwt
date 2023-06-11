import { Claims, JwtClient } from '../index.js';
import bench from 'benchmark';
import chalk from 'chalk';
import fastJwt from 'fast-jwt';
import * as jose from 'jose';
import jwt from 'jsonwebtoken';

const suite = new bench.Suite('Decode (No Verification)');

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

const joseToken = await joseSign(payload);
const jwtSigned = jwt.sign(payload, secret);

const signer = fastJwt.createSigner({ key: secret });
const fastJwtDecode = fastJwt.createDecoder();
const fastJwtToken = signer(payload);

const claims = new Claims(JSON.stringify(payload), 60000);
const ctJwtToken = client.signClaims(claims);

suite
  .add(
    'jsonwebtoken',
    () => {
      jwt.decode(jwtSigned);
    },
    { minSamples },
  )
  .add(
    'jose',
    () => {
      jose.decodeJwt(joseToken);
    },
    { minSamples },
  )
  .add(
    'fast-jwt',
    () => {
      fastJwtDecode(fastJwtToken);
    },
    { minSamples },
  )
  .add(
    '@carbonteq/jwt',
    () => {
      client.decode(ctJwtToken);
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
