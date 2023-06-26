# Faster JWT (rust bindings) with an (optional) LRU cache

---

## Benchmarks

Benchmarks were performed using [benchmark](https://www.npmjs.com/package/benchmark) package, against [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken), [jose](https://www.npmjs.com/package/jose) and [fast-jwt](https://www.npmjs.com/package/fast-jwt). It was not done to cast shadow over those packages, merely to check whether this package is performant enough or not.

Machine Details:

- OS: Ubuntu 22.04
- Processor: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz - Threads: 6 * 2
- Memory: 16G

**DISCLAIMER: Always take benchmarks like this with a grain of salt, as they may not always be indicative of good performance. And performance may not be the top thing to consider when choosing a package for solving your problem (unless the problem is that of performance itself). It would be best to perform these benchmarks on your own machine/deployment environment before making any decision.**

### Signing Benchmark ([bench/sign.mjs](./bench/sign.mjs))

```
jsonwebtoken x 1,982 ops/sec ±0.57% (189 runs sampled)
jose x 55,908 ops/sec ±0.78% (177 runs sampled)
fast-jwt x 52,656 ops/sec ±0.59% (186 runs sampled)
@carbonteq/jwt x 362,540 ops/sec ±0.35% (192 runs sampled)
@carbonteq/jwt#signClaims x 210,083 ops/sec ±2.29% (184 runs sampled)

SUITE <Sign token>: Fastest is @carbonteq/jwt
```

### Verifying Token ([bench/verify.mjs](./bench/verify.mjs))

```
jsonwebtoken x 2,068 ops/sec ±0.46% (187 runs sampled)
jose x 55,797 ops/sec ±0.29% (182 runs sampled)
fast-jwt x 68,474 ops/sec ±0.79% (182 runs sampled)
@carbonteq/jwt x 166,543 ops/sec ±0.73% (189 runs sampled)

SUITE <Verify Token>: Fastest is @carbonteq/jwt
```
