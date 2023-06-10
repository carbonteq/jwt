import bench from "benchmark";
import jwt from "jsonwebtoken";
import fastJwt from "fast-jwt";
import * as jose from "jose";
import { Claims, sign, Signer } from "../index.js";

const suite = new bench.Suite();

const secret = "somelongsecretasdbnakwfbjawf";
const encodedKey = new TextEncoder().encode(secret);
const payload = { userId: "abc123" };

let myEncoder = new Signer(secret);
let myEncoder2 = Signer.fromBufferKey(Buffer.from(secret));

const joseSign = async (payload) => {
	const s = new jose.SignJWT(payload);
	return s.setProtectedHeader({ alg: "HS256" }).sign(encodedKey);
	// const key = jose.JWK.asKey(secret);
	// return await jose.JWT.sign(payload, key);
};

suite
	.add("jsonwebtoken#sign", {
		defer: true,
		fn: function (deferred) {
			jwt.sign(payload, secret);
			deferred.resolve();
		},
	})
	.add("jose#sign", {
		defer: true,
		fn: function (deferred) {
			joseSign(payload).then(() => deferred.resolve());
			// const s = new jose.SignJWT(payload);
			// s.setProtectedHeader({ alg: "HS256" }).sign(encodedKey).then(defer);
		},
	})
	.add("fastjwt#sign", {
		defer: true,
		fn: function (deferred) {
			const signer = fastJwt.createSigner({ key: secret });
			signer(payload);
			deferred.resolve();
		},
	})
	.add("faster-jwt#sign", {
		defer: true,
		fn: function (deferred) {
			const claims = new Claims(JSON.stringify(payload), 1000);
			sign(claims, secret);
			deferred.resolve();
		},
	})
	.add("faster-jwt#signWithEncoder", {
		defer: true,
		fn: function (deferred) {
			const claims = new Claims(JSON.stringify(payload), 1000);
			myEncoder.sign(claims);
			deferred.resolve();
		},
	})
	.add("faster-jwt#signWithEncoder2", {
		defer: true,
		fn: function (deferred) {
			const claims = new Claims(JSON.stringify(payload), 1000);
			myEncoder2.sign(claims);
			deferred.resolve();
		},
	})
	.on("cycle", (e) => {
		console.log(String(e.target));
	})
	.on("complete", function () {
		console.log("Fastest is " + this.filter("fastest").map("name"));
	})
	.run({ async: true });
