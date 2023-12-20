import { FwTracer } from "@ndn/fw";
import { Certificate, ECDSA, generateSigningKey, type KeyChain, RSA, SigningAlgorithm, NamedSigner, NamedVerifier, CertNaming } from "@ndn/keychain";
import { FwHint, Name, type Signer } from "@ndn/packet";
import { DataStore, RepoProducer, PrefixRegStatic } from "@ndn/repo";
import { openKeyChain, openUplinks } from "@ndn/cli-common";
import { CaProfile, Server } from "@ndn/ndncert";
import { ServerOidcChallenge } from "./oidc-challenge.ts";
import { getSafeBag } from "./keychain-bypass.ts" 
import memdown from "memdown";
import yargs from "yargs/yargs";

let caPvt: NamedSigner.PrivateKey;
let caPub: NamedVerifier.PublicKey;
let caCert: Certificate;
let caCertName: string;
let caProfile: CaProfile;
let oidcClientId: string;
let oidcSecret: string;
let caPrefix: string;
let maxValidity: number;
let repoName: string;
let repoProducer: RepoProducer;

const repo = new DataStore(memdown());
const requestHeader: Record<string, string> = {};
const requestBody = new URLSearchParams();
export const keyChain: KeyChain = openKeyChain();

const runCA = async () => {
  const fwName = new Name(repoName);
  const repoFwHint = new FwHint(fwName);
  requestHeader["Content-Type"] = "application/x-www-form-urlencoded";
  requestBody.append("client_id", oidcClientId);
  requestBody.append("client_secret", oidcSecret);
  requestBody.append("scope", "openid");
  requestBody.append("grant_type", "authorization_code");

  await openUplinks();
  await openKeyChain()
  console.log(caCertName.toString())
  const safeBag = await getSafeBag(caCertName, "PASSPHRASE");
  caCert = safeBag.certificate;
  repo.insert(caCert.data);
  repoProducer = RepoProducer.create(repo, { reg: PrefixRegStatic(fwName, CertNaming.toKeyName(caCert.name)) });

  const algoList: SigningAlgorithm[] = [ECDSA, RSA];
  const [algo, key] = await caCert.importPublicKey(algoList);
  const pkcs8 = await safeBag.decryptKey("PASSPHRASE");
  [caPvt, caPub] = await generateSigningKey(caCert.name, algo, { importPkcs8: [pkcs8, key.spki] });
  caPrefix = caCert.name.getPrefix(-4).toString();
  caProfile = await CaProfile.build({
    prefix: new Name(caPrefix),
    info: caPrefix + " CA",
    probeKeys: [],
    maxValidityPeriod: maxValidity,
    cert: caCert,
    signer: caPvt,
    version: Date.now(),
  });
  console.log(caProfile.toJSON());
  const fullName = await caProfile.cert.data.computeFullName();
  console.log("CA certificate full name is ", fullName.toString());
  return Server.create({
    profile: caProfile,
    repo,
    repoFwHint,
    signer: caPvt,
    challenges: [
      new ServerOidcChallenge(
        "google-oidc",
        60000,
        1,
        {
          requestHeader,
          requestBody,
          requestUrl: "https://oauth2.googleapis.com/token",
          pubKeyUrl: "https://www.googleapis.com/oauth2/v3/certs",
          assignmentPolicy: (sub, id) => {
            console.log(sub + " applied by " + id);
            const parts = id.split("@");
            if (parts.length != 2) {
              throw new Error("Email address not correct");
            }
            const [account, domain] = parts;
            const subnames = domain.split(".").reverse();
            const assignedName = new Name(caPrefix).append(...subnames).append(
              account,
            );
            return Promise.resolve(assignedName);
          },
        },
      ),
    ],
  });
};

if (import.meta.main) {
  const parser = yargs(Deno.args).options({
    caCertName: { type: "string" },
    maxValidity: { type: "number", default: 86400000*30 },
    repoName: { type: "string" },
    oidcId: { type: "string" },
    oidcSecret: { type: "string" }
  });

  FwTracer.enable()
  const argv = await parser.argv;
  caCertName = argv.caCertName;
  maxValidity = argv.maxValidity;
  repoName = argv.repoName;
  oidcClientId = argv.oidcId;
  oidcSecret = argv.oidcSecret;

  const server = await runCA();
  Deno.addSignalListener("SIGINT", () => {
    console.log("Stopped by Ctrl+C");
    server.close();
    repoProducer.close();
    Deno.exit();
  });
}
