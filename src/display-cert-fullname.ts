import {
  Certificate,
  CertNaming,
  ECDSA,
  generateSigningKey,
  type KeyChain,
  NamedSigner,
  NamedVerifier,
  RSA,
  SigningAlgorithm,
} from "@ndn/keychain";
import { openKeyChain } from "@ndn/cli-common";
import { getSafeBag } from "./keychain-bypass.ts";
import yargs from "yargs/yargs";

let caPvt: NamedSigner.PrivateKey;
let caPub: NamedVerifier.PublicKey;
let caCert: Certificate;

export const keyChain: KeyChain = openKeyChain();

const displayCertFullname = async (caCertName: string) => {
  await openKeyChain();
  const safeBag = await getSafeBag(caCertName, "PASSPHRASE");
  caCert = safeBag.certificate;

  const algoList: SigningAlgorithm[] = [ECDSA, RSA];
  const [algo, key] = await caCert.importPublicKey(algoList);
  const pkcs8 = await safeBag.decryptKey("PASSPHRASE");
  [caPvt, caPub] = await generateSigningKey(caCert.name, algo, { importPkcs8: [pkcs8, key.spki] });
  return (await caCert.data.computeFullName()).toString();
};

if (import.meta.main) {
  const parser = yargs(Deno.args).options({
    caCertName: { type: "string" },
  });
  const argv = await parser.argv;
  console.log(await displayCertFullname(argv.caCertName));
}
