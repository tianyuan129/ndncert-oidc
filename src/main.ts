import { Certificate, generateSigningKey, type NamedSigner, type NamedVerifier } from "@ndn/keychain";
import { FwHint, Name, type Signer } from "@ndn/packet";
import { DataStore, RepoProducer, PrefixRegStatic } from "@ndn/repo";

import { CaProfile, Server, requestCertificate} from "@ndn/ndncert";
import { ClientOidcChallenge, ServerOidcChallenge } from "./oidc-challenge.ts";
import memdown from "memdown";

let caPvt: NamedSigner.PrivateKey;
let caPub: NamedVerifier.PublicKey;
let caCert: Certificate;
let caSigner: Signer;
let caProfile: CaProfile;
let reqPvt: NamedSigner.PrivateKey;
let reqPub: NamedVerifier.PublicKey;
let reqCert: Certificate;
let accessCode: string;

const repo = new DataStore(memdown());
const fwName = new Name("/fh");
const repoFwHint = new FwHint(fwName);
const repoProducer = RepoProducer.create(repo, { reg: PrefixRegStatic(fwName) });
const requestHeader: Record<string, string> = {};
const requestBody = new URLSearchParams();
const oidcClientId = "960085847794-jgd05gg3b6l3ijm8khdiu8du8hb44h2i.apps.googleusercontent.com";
const oidcSecret = "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";
requestHeader["Content-Type"] = "application/x-www-form-urlencoded";
requestBody.append("redirect_uri", 'http://localhost:8085');
requestBody.append("client_id", oidcClientId);
requestBody.append("client_secret", oidcSecret);
requestBody.append("scope", "openid");
requestBody.append("grant_type", "authorization_code");

export class GoogleServerOidcChallenge extends ServerOidcChallenge {
  public readonly challengeId = "google-oidc";
  public readonly timeLimit = 60000;
  public readonly retryLimit = 1;
}

export class GoogleClientOidcChallenge extends ClientOidcChallenge {
  public readonly challengeId = "google-oidc";
}

const prepareKeys = async () => {
  [caPvt, caPub] = await generateSigningKey("/authority");
  caCert = await Certificate.selfSign({ privateKey: caPvt, publicKey: caPub });
  caSigner = caPvt.withKeyLocator(caCert.name);
  caProfile = await CaProfile.build({
    prefix: new Name("/authority"),
    info: "authority\nCA",
    probeKeys: ["uid"],
    maxValidityPeriod: 86400000,
    cert: caCert,
    signer: caSigner,
    version: 7,
  });
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
  const OidcChallenge = new GoogleClientOidcChallenge(oidcClientId, accessCode);

  [reqPvt, reqPub] = await generateSigningKey("/requester");
  reqCert = await requestCertificate({
    profile: caProfile,
    privateKey: reqPvt,
    publicKey: reqPub,
    challenges: [OidcChallenge],
  });
  console.log(`${reqCert.data.name}\n`);
};
accessCode = Deno.args[0];
prepareKeys()