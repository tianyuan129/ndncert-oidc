import { Random } from "./dep.ts";
import { FwTracer } from "@ndn/fw";
import { Certificate, generateSigningKey, type NamedSigner, type NamedVerifier } from "@ndn/keychain";
import { FwHint, Name, type Signer } from "@ndn/packet";
import { DataStore, RepoProducer, PrefixRegStatic } from "@ndn/repo";
import { exitClosers, openUplinks } from "@ndn/cli-common";
import { CaProfile, Server } from "@ndn/ndncert";
import { ServerOidcChallenge } from "./oidc-challenge.ts";
import memdown from "memdown";
import yargs from "yargs/yargs";

let caPvt: NamedSigner.PrivateKey;
let caPub: NamedVerifier.PublicKey;
let caCert: Certificate;
let caSigner: Signer;
let caProfile: CaProfile;
let oidcClientId: string;
let oidcSecret: string;
let redirectUrl: string;
let caPrefix: string;
let maxValidity: number;
let repoName: string;
let repoProducer: RepoProducer;

const repo = new DataStore(memdown());
const requestHeader: Record<string, string> = {};
const requestBody = new URLSearchParams();

const runCA = async () => {
  const fwName = new Name(repoName);
  const repoFwHint = new FwHint(fwName);
  repoProducer = RepoProducer.create(repo, { reg: PrefixRegStatic(fwName) });

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
  console.log(caProfile.toJSON());
  const fullName = await caProfile.cert.data.computeFullName();
  console.log("CA certificate full name is ", fullName.toString());
  return Server.create({
    profile: caProfile,
    repo,
    repoFwHint,
    signer: caSigner,
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
  exitClosers.push(server);
  await exitClosers.wait();
};

if (import.meta.main) {
  const parser = yargs(Deno.args).options({
    caPrefix: { type: "string" },
    maxValidity: { type: "number", default: 86400000 },
    repoName: { type: "string" },
    oidcId: { type: "string" },
    oidcSecret: { type: "string" },
    redirectUrl: { type: "string" },
  });

  FwTracer.enable()
  const argv = await parser.argv;
  caPrefix = argv.caPrefix;
  maxValidity = argv.maxValidity;
  repoName = argv.repoName;
  oidcClientId = argv.oidcId;
  oidcSecret = argv.oidcSecret;
  redirectUrl = argv.redirectUrl;

  const server = await runCA();
  Deno.addSignalListener("SIGINT", () => {
    console.log("Stopped by Ctrl+C");
    server.close();
    repoProducer.close();
    Deno.exit();
  });
}
