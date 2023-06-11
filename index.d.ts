/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

export interface ClaimOpts {
  aud?: string
  iat?: Number
  iss?: string
  jti?: string
  nbf?: Number
  sub?: string
}
export class Claims {
  data: Record<string, any>
  exp: Number
  aud?: string
  iat?: Number
  iss?: string
  jti?: string
  nbf?: Number
  sub?: string
  constructor(data: Record<string, any>, expiresInSeconds: number, opts?: ClaimOpts | undefined | null)
}
export class JwtClient {
  constructor(secretKey: string)
  static fromBufferKey(secretKey: Buffer): JwtClient
  sign(data: Record<string, any>, expiresInSeconds: number, claimOpts?: ClaimOpts | undefined | null): string
  signClaims(claims: Claims): string
  verify(token: string): boolean
  verifyAndDecode(token: string): Claims
}
