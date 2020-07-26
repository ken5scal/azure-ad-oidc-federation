import { TimeUtils } from "@azure/msal-common"
import { v4 as uuid } from "uuid";
import base64url from "base64url";
import axios from "axios";
import crypto from 'crypto';
import { UserAgentApplication, AuthenticationParameters, AuthResponse }  from "@azure/msal";
import { StringDict } from '@azure/msal/lib-commonjs/MsalTypes';

const AzureADOIDCMetadata = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
const clientId = process.env['clientId'] || 'someId'
const tenantId = process.env['tenantId']
const msalInstance = new UserAgentApplication({auth: {
  clientId: clientId,
  authority: `https://login.microsoftonline.com/${tenantId}`
}})

let sid: string = 'fake'

interface IdTokenHeader {
  typ: string;
  alg: string;
  kid: string;
}

interface AzureADRSAJWK {
  kty: string;
  use: string;
  kid: string;
  x5t: string;
  n: string;
  e: string;
  x5c: string[];
  issuer: string;
}

axios.defaults.headers.get['Content-Type'] = 'application/json'
window.addEventListener("load", async () => {
  const loginRequest: AuthenticationParameters = {scopes: ["openid"], state: uuid(), sid: sid}
  msalInstance.ssoSilent(loginRequest)
  .then(async => validateIdToken)
  .catch(error => {
    loginRequest["sid"] = undefined
    msalInstance.loginPopup(loginRequest)
    .then(async resp => validateIdToken)
  })
})

async function validateIdToken(resp: AuthResponse): Promise<void> {
  try {
    const jwk = await getJWK(resp.idToken.rawIdToken)

    if (!validateIdTokenClaims(resp.idTokenClaims)) {
      throw Error("ID Token has invalid claims");
    }

    if (!jwk || !(validateIdTokenSignature(jwk, resp.idToken.rawIdToken))) {
      throw Error("IdToken has invalid signature");
    }

    sid = resp.idTokenClaims['sid']
  } catch (error) {
    console.error(error)
  }
}

async function getJWK(idToken: string): Promise<AzureADRSAJWK | undefined> {
  const splitted = idToken.split(".")
  const header: IdTokenHeader = JSON.parse(base64url.decode(splitted[0]))

  const meta = await axios.get(AzureADOIDCMetadata)
  const resp = await axios.get(meta.data['jwks_uri'])
  const keys: AzureADRSAJWK[] = resp.data["keys"]
  keys.filter((key) => {
    if (!header.alg.includes('RS') || key.kty !== 'RSA') {
      throw Error("algorithm is not RSA")
    }
    
    if (key.hasOwnProperty('use') && key.use !== 'sig') {
      return false
    }
    
    if (!(key.x5c && key.x5c.length)) {
      return false
    }

    if (!(key.n && key.e)) {
      return false
    }

    return (key.kid === header.kid)
  })
  return keys[0]
}

function validateIdTokenClaims(idTokenClaims: StringDict): boolean {
  const now = TimeUtils.nowSeconds();
  const aud = idTokenClaims["aud"]
  const iat: number = +idTokenClaims["iat"]
  const nbf: number = +idTokenClaims["nbf"]
  const exp: number = +idTokenClaims["exp"]
  return (aud == clientId && nbf <= now && exp > now && iat !== null)
}

function validateIdTokenSignature(key: AzureADRSAJWK, idToken: string) {      
  let jwk: string
  if (key.x5c && key.x5c.length) {
    jwk = certToPEM(key.x5c[0])
   } else {
    jwk = rsaPubKeyToPEM(key.n, key.e)
  }

  const splitted = idToken.split(".")
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(splitted[0] + "." + splitted[1])
  return verifier.verify(certToPEM(key.x5c[0]), splitted[2], 'base64')
}

function certToPEM(cert: string): string {
  const re = /.{1,64}/g
  let match: RegExpMatchArray | null = cert.match(re)
  if (match !== null) {
    cert = match.join('\n');
  }
  
  return `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`;
}

// calculating rsa pulic key from modulus and exponent is from
// https://github.com/auth0/node-jwks-rsa/blob/d842be9fc24cc3eef53ae1b41ef6a36df0bf3b33/src/utils.js#L35
function rsaPubKeyToPEM(modulusB64: string, exponentB64: string): string {
  const modulus = new Buffer(modulusB64, 'base64');
  const exponent = new Buffer(exponentB64, 'base64');
  const modulusHex = prepadSigned(modulus.toString('hex'));
  const exponentHex = prepadSigned(exponent.toString('hex'));
  const modlen = modulusHex.length / 2;
  const explen = exponentHex.length / 2;

  const encodedModlen = encodeLengthHex(modlen);
  const encodedExplen = encodeLengthHex(explen);
  const encodedPubkey = '30' +
    encodeLengthHex(modlen + explen + encodedModlen.length / 2 + encodedExplen.length / 2 + 2) +
    '02' + encodedModlen + modulusHex +
    '02' + encodedExplen + exponentHex;

  const der = new Buffer(encodedPubkey, 'hex')
    .toString('base64');


  const re = /.{1,64}/g
  let match: RegExpMatchArray | null = der.match(re)
  let pem = '-----BEGIN RSA PUBLIC KEY-----\n';
  if (match !== null) {
    pem += `${match.join('\n')}`;
  }
  
  pem += '\n-----END RSA PUBLIC KEY-----\n';
  return pem;
}

function prepadSigned(hexStr: string): string {
  const msb = hexStr[0];
  if (msb < '0' || msb > '7') {
    return `00${hexStr}`;
  }
  return hexStr;
}

function encodeLengthHex(n: number) {
  if (n <= 127) {
    return toHex(n);
  }
  const nHex = toHex(n);
  const lengthOfLengthByte = 128 + nHex.length / 2;
  return toHex(lengthOfLengthByte) + nHex;
}

function toHex(number: number) {
  const nstr = number.toString(16);
  if (nstr.length % 2) {
    return `0${nstr}`;
  }
  return nstr;
}