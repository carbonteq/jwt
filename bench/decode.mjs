import bench from "benchmark";
import jwt from "jsonwebtoken";
import fastJwt from "fast-jwt";
import * as jose from "jose";
import { Claims, sign, decodeToken } from "../index.js";

const suite = new bench.Suite();

const secret = "somelongsecretasdbnakwfbjawf";
const encodedKey = new TextEncoder().encode(secret);
const payload = { userId: "abc123" };

const joseSign = async (payload) => {
	const s = new jose.SignJWT(payload);
	return s.setProtectedHeader({ alg: "HS256" }).sign(encodedKey);
	// const key = jose.JWK.asKey(secret);
	// return await jose.JWT.sign(payload, key);
};

const joseSigned = await joseSign(payload);
const jwtSigned = jwt.sign(payload, secret);

const signer = fastJwt.createSigner({ key: secret });
const fastJwtDecode = fastJwt.createDecoder();
const fastJwtSigned = signer(payload);

const currentTimeStamp = new Date().getTime();
const claims = new Claims(JSON.stringify(payload), currentTimeStamp + 60000);
const fasterJwtSigned = sign(claims, secret);

suite
	.add("jsonwebtoken#decode", {
		defer: true,
		fn: function (deferred) {
			jwt.decode(jwtSigned);
			deferred.resolve();
		},
	})
	.add("jose#decode", {
		defer: true,
		fn: function (deferred) {
			jose.decodeJwt(joseSigned);
			deferred.resolve();
		},
	})
	.add("fastjwt#decode", {
		defer: true,
		fn: function (deferred) {
			fastJwtDecode(fastJwtSigned);
			deferred.resolve();
		},
	})
	.add("faster-jwt#decode", {
		defer: true,
		fn: function (deferred) {
			decodeToken(fasterJwtSigned, secret);
			deferred.resolve();
		},
	})
	.on("cycle", (e) => {
		console.log(String(e.target));
	})
	.on("complete", function () {
		console.log("\nFastest is " + this.filter("fastest").map("name"));
	})
	.run({ async: true });
