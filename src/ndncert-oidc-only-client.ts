import { Certificate, generateSigningKey, type NamedSigner, type NamedVerifier } from "@ndn/keychain";
import { CaProfile, ProbeResponse, retrieveCaProfile, requestCertificate} from "@ndn/ndncert";
import { openUplinks } from "@ndn/cli-common";
import { Name } from "@ndn/packet";
import { ClientOidcChallenge } from "./oidc-challenge.ts";
import yargs from 'yargs/yargs';


let reqName: string;
let caProfile: CaProfile;
let reqPvt: NamedSigner.PrivateKey;
let reqPub: NamedVerifier.PublicKey;
let reqCert: Certificate;
let accessCode: string;
let oidcClientId : string;

export class GoogleClientOidcChallenge extends ClientOidcChallenge {
  public readonly challengeId = "google-oidc";
}

const runClient = async () => {
  const OidcChallenge = new GoogleClientOidcChallenge(oidcClientId, accessCode);

  [reqPvt, reqPub] = await generateSigningKey(reqName);
  reqCert = await requestCertificate({
    profile: caProfile,
    privateKey: reqPvt,
    publicKey: reqPub,
    challenges: [OidcChallenge],
  });
  console.log(`${reqCert.data.name}\n`);
};


const parser = yargs(Deno.args).options({
  reqName: { type: 'string'},
  caCertFullNameStr: { type: 'string'},
  oidcId: { type: 'string'},
  accessCode: { type: 'string'}
});


(async() => {
  const argv = await parser.argv;
  reqName = argv.reqName;

  const caCertFullName = new Name(argv.caCertFullNameStr);
  if (ProbeResponse.isCaCertFullName(caCertFullName)) {
    await openUplinks();
    caProfile = await retrieveCaProfile({ caCertFullName: caCertFullName });
    console.log(caProfile.toJSON())
  }
  else {
    console.log("You should input a CA's full certificate name")
  }
  oidcClientId = argv.oidcId;
  accessCode = argv.accessCode;
  runClient()
})();
