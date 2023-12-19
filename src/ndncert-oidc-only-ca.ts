import { Certificate, generateSigningKey, type NamedSigner, type NamedVerifier } from "@ndn/keychain";
import { FwHint, Name, type Signer } from "@ndn/packet";
import { DataStore, RepoProducer, PrefixRegStatic } from "@ndn/repo";
import { openUplinks } from "@ndn/cli-common";
import { CaProfile, Server } from "@ndn/ndncert";
import { ClientOidcChallenge, ServerOidcChallenge } from "./oidc-challenge.ts";
import memdown from "memdown";
import yargs from 'yargs/yargs';

let caPvt: NamedSigner.PrivateKey;
let caPub: NamedVerifier.PublicKey;
let caCert: Certificate;
let caSigner: Signer;
let caProfile: CaProfile;
let oidcClientId : string;
let oidcSecret: string;
let redirectUrl: string;
let caPrefix: string;
let maxValidity: number;
let repoName: string;

const repo = new DataStore(memdown());
const requestHeader: Record<string, string> = {};
const requestBody = new URLSearchParams();
export class GoogleServerOidcChallenge extends ServerOidcChallenge {
  public readonly challengeId = "google-oidc";
  public readonly timeLimit = 60000;
  public readonly retryLimit = 1;
}

export class GoogleClientOidcChallenge extends ClientOidcChallenge {
  public readonly challengeId = "google-oidc";
}

const runCA = async () => {
  const fwName = new Name(repoName);
  const repoFwHint = new FwHint(fwName);
  const repoProducer = RepoProducer.create(repo, { reg: PrefixRegStatic(fwName) });

  requestHeader["Content-Type"] = "application/x-www-form-urlencoded";
  requestBody.append("redirect_uri", redirectUrl);
  requestBody.append("client_id", oidcClientId);
  requestBody.append("client_secret", oidcSecret);
  requestBody.append("scope", "openid");
  requestBody.append("grant_type", "authorization_code");
  
  await openUplinks();
  [caPvt, caPub] = await generateSigningKey(caPrefix);
  caCert = await Certificate.selfSign({ privateKey: caPvt, publicKey: caPub });
  caSigner = caPvt.withKeyLocator(caCert.name);
  caProfile = await CaProfile.build({
    prefix: new Name(caPrefix),
    info: caPrefix + " CA",
    probeKeys: [],
    maxValidityPeriod: maxValidity,
    cert: caCert,
    signer: caSigner,
    version: Date.now(),
  });
  console.log(caProfile.toJSON())
  const fullName = await caProfile.cert.data.computeFullName();
  console.log("CA certificate full name is ",fullName.toString())
  const server = Server.create({
    profile: caProfile,
    repo,
    repoFwHint,
    signer: caSigner,
    challenges: [new GoogleServerOidcChallenge(
      requestHeader,
      requestBody,
      "https://oauth2.googleapis.com/token",
      "https://www.googleapis.com/oauth2/v3/certs",
      async(_sub, _id) => {
        console.log(_sub + " applied by " + _id);
      })
    ]
  });
};

const parser = yargs(Deno.args).options({
  caPrefix: { type: 'string'},
  maxValidity: { type: 'number', default: 86400000},
  repoName: { type: 'string'},
  oidcId: { type: 'string'},
  oidcSecret: { type: 'string'},
  redirectUrl: { type: 'string'},
});

(async() => {
  const argv = await parser.argv;
  caPrefix = argv.caPrefix;
  maxValidity = argv.maxValidity;
  repoName = argv.repoName;
  oidcClientId = argv.oidcId;
  oidcSecret = argv.oidcSecret;
  redirectUrl = argv.redirectUrl;
  runCA()
})();
