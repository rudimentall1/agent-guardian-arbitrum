import { ethers } from "hardhat";

export async function signTypedDataDigest(
  signer: any,
  domain: any,
  types: any,
  value: any
): Promise<string> {
  if (typeof signer.signTypedData === "function") {
    return await signer.signTypedData(domain, types, value);
  }

  const digest = ethers.TypedDataEncoder.hash(domain, types, value);

  if (signer.signingKey) {
    const sig = signer.signingKey.sign(digest);
    return ethers.Signature.from(sig).serialized;
  }

  throw new Error("Signer does not support EIP-712 signing");
}
