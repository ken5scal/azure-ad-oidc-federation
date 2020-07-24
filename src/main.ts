import Vue from 'vue'
import App from './App.vue'
import { PublicClientApplication, AccountInfo, AuthenticationResult, Configuration, LogLevel, EndSessionRequest, PopupRequest } from "@azure/msal-browser";
import { TimeUtils, AuthError } from "@azure/msal-common"
import { v4 as uuid } from "uuid";
import base64url from "base64url";
import axios from "axios";
import crypto from 'crypto'

Vue.config.productionTip = false
    new Vue({
      render: h => h(App),
    }).$mount('#app')

const AzureADOIDCMetadata = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
const clientId = '233198da-6ed2-40f0-8e65-1d235385e2fe'
const tenantId = '36a6e4b2-e620-44c2-897b-22b1d394354a'
const msalConfig: Configuration = {
  auth: {
    clientId: clientId,
    authority: `https://login.microsoftonline.com/${tenantId}`
  }
}

let msalObj: PublicClientApplication = new PublicClientApplication(msalConfig)
axios.defaults.headers.get['Content-Type'] = 'application/json'

window.addEventListener("load", async () => {
  loadAuthModule()
})

function loadAuthModule(): void {
  let accounts = msalObj.getAllAccounts();
  if (accounts === null) {
    login()
  }
}

function login(): void {
  const state = uuid();
  const nonce = uuid();
  const loginRequest: PopupRequest =  {scopes:[], state: state, nonce: nonce, codeChallenge: uuid(), codeChallengeMethod: "S256"}
  msalObj.loginPopup(loginRequest)
    .then((resp: AuthenticationResult) => {
      const now = TimeUtils.nowSeconds();
      const idTokenNonce = resp.idTokenClaims["nonce"]
      const aud = resp.idTokenClaims["aud"]
      const iat: number = +resp.idTokenClaims["iat"]
      const nbf: number = +resp.idTokenClaims["nbf"]
      const exp: number = +resp.idTokenClaims["exp"]
      const splitted = resp.idToken.split(".")
      const header: IdTokenHeader = JSON.parse(base64url.decode(splitted[0]))

      if (resp.state !== state || idTokenNonce !== nonce || aud != clientId ||
        nbf > now || exp <= now || iat === null) {
        return
      }
    
      axios.get(AzureADOIDCMetadata)
      .then(resp => {
        axios.get(resp.data["jwks_uri"])
        .then(resp => {
          const keys: AzureADRSAJWK[] = resp.data["keys"]
          keys.filter((key) => {
            if (!header.alg.includes('RS') || key.kty !== 'RSA') {
              return false
            }
            if (key.hasOwnProperty('use') && key.use !== 'sig') {
              return false
            }
            return (key.x5c && key.x5c.length) || (key.n && key.e)
          })
          .map((key) => {
            if (key.kid !== header.kid) {
              return
            }
            
            let jwk: string
            // has certificate chain?
            if (key.x5c && key.x5c.length) {
              jwk = certToPEM(key.x5c[0])
            } else {
              jwk = rsaPubKeyToPEM(key.n, key.e)
            }

            const verifier = crypto.createVerify('RSA-SHA256');
            verifier.update(splitted[0] + "." + splitted[1])
            if (!verifier.verify(certToPEM(key.x5c[0]), splitted[2], 'base64')) {
              logout();
            }
          })
        })
      })
  }).catch((err: AuthError) => {
    logout()
  })
}

function logout(): void {
  msalObj.logout();
}

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

function certToPEM(cert: string): string {
  const re = /.{1,64}/g
  let match: RegExpMatchArray | null = cert.match(re)
  if (match !== null) {
    cert = match.join('\n');
  }
  
  return `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`;
}

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