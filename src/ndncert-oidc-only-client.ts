import { Certificate, generateSigningKey, type NamedSigner, type NamedVerifier } from "@ndn/keychain";
import { CaProfile, ProbeResponse, requestCertificate, retrieveCaProfile } from "@ndn/ndncert";
import { openUplinks } from "@ndn/cli-common";
import { Name } from "@ndn/packet";
import { ClientOidcChallenge } from "./oidc-challenge.ts";
import yargs from "yargs/yargs";

let reqName: string;
let caProfile: CaProfile;
let reqPvt: NamedSigner.PrivateKey;
let reqPub: NamedVerifier.PublicKey;
let reqCert: Certificate;
let accessCode: string;
let oidcId: string;

const runClient = async () => {
  const OidcChallenge = new ClientOidcChallenge("google-oidc", {
    oidcId,
    accessCode,
  });

  [reqPvt, reqPub] = await generateSigningKey(reqName);
  reqCert = await requestCertificate({
    profile: caProfile,
    privateKey: reqPvt,
    publicKey: reqPub,
    challenges: [OidcChallenge],
  });
  console.log(`${reqCert.data.name}\n`);
};

if (import.meta.main) {
  const parser = yargs(Deno.args).options({
    reqName: { type: "string" },
    caCertFullNameStr: { type: "string" },
    oidcId: { type: "string" },
    accessCode: { type: "string" },
  });

  const argv = await parser.argv;
  reqName = argv.reqName;

  const caCertFullName = new Name(argv.caCertFullNameStr);
  if (ProbeResponse.isCaCertFullName(caCertFullName)) {
    await openUplinks();
    caProfile = await retrieveCaProfile({ caCertFullName: caCertFullName });
    console.log(caProfile.toJSON());
  } else {
    console.log("You should input a CA's full certificate name");
  }
  oidcId = argv.oidcId;
  accessCode = argv.accessCode;
  await runClient();

  Deno.exit();
}
