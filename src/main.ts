import Vue from 'vue'
import App from './App.vue'
import { PublicClientApplication, AccountInfo, AuthenticationResult, Configuration, LogLevel, EndSessionRequest, PopupRequest } from "@azure/msal-browser";
import { TimeUtils, AuthError } from "@azure/msal-common"
import { v4 as uuid } from "uuid";

Vue.config.productionTip = false
    new Vue({
      render: h => h(App),
    }).$mount('#app')

const clientId = '233198da-6ed2-40f0-8e65-1d235385e2fe'
const tenantId = '36a6e4b2-e620-44c2-897b-22b1d394354a'
const msalConfig: Configuration = {
  auth: {
    clientId: clientId,
    authority: `https://login.microsoftonline.com/${tenantId}`
  },
  cache: {
    storeAuthStateInCookie: true
  },
  system: {
            loggerOptions: {
                loggerCallback: (level, message, containsPii) => {
                    if (containsPii) {	
                        return;	
                    }
                    switch (level) {	
                        case LogLevel.Error:	
                          console.error(message);	
                            return;	
                        case LogLevel.Info:	
                            console.info(message);	
                            return;	
                        case LogLevel.Verbose:	
                            console.debug(message);	
                            return;	
                        case LogLevel.Warning:	
                            console.warn(message);	
                            return;	
                    }
                }
            }
        }
}

let msalObj: PublicClientApplication = new PublicClientApplication(msalConfig)

window.addEventListener("load", async () => {
  loadAuthModule()
})

function loadAuthModule(): void {
  const { location: { hash } } = window;
  let accounts = msalObj.getAllAccounts();
  if (accounts === null) {
    login()
  }
}

function login(): void {
  let state = uuid();
  let nonce = uuid();
  let loginRequest: PopupRequest =  {scopes:[], state: state, nonce: nonce, codeChallenge: uuid(), codeChallengeMethod: "S256"}
  msalObj.loginPopup(loginRequest).then((resp: AuthenticationResult) => {
    let now = TimeUtils.nowSeconds();
    let idTokenNonce = resp.idTokenClaims["nonce"]
    let aud = resp.idTokenClaims["aud"]
    let iat: number = +resp.idTokenClaims["iat"]
    let nbf: number = +resp.idTokenClaims["nbf"]
    let exp: number = +resp.idTokenClaims["exp"]
    if (resp.state !== state || idTokenNonce !== nonce || aud != clientId ||
      nbf > now || exp <= now || iat === null || validateJWTSignature) {
        console.log(resp.idTokenClaims)
        console.log(aud, clientId)
        console.log(nbf, now)
        console.log(exp, now)
      const logOutRequest: EndSessionRequest = {
        account: resp.account
      };
      msalObj.logout(logOutRequest)
      return
    }
  }).catch((hoge: AuthError) => {
    
  })

  function validateJWTSignature(idtoken: string): boolean {
    return true
  }
}