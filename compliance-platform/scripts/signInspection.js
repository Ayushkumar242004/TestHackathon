// scripts/signInspection.js  (ESM version)
import { ethers } from "ethers";
import dotenv from "dotenv";
dotenv.config();

async function main() {
  const rpc = process.env.RPC || "http://127.0.0.1:8545";
  const provider = new ethers.providers.JsonRpcProvider(rpc);

  const inspectorPk = process.env.INSPECTOR_PK;
  if (!inspectorPk) throw new Error("Set INSPECTOR_PK in .env");
  const inspectorWallet = new ethers.Wallet(inspectorPk, provider);
  const inspector = inspectorWallet.address;

  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (!contractAddress) throw new Error("Set CONTRACT_ADDRESS in .env");

  const ipfsCid = process.env.IPFS_CID || "QmExampleCID";
  const contentHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ipfs://" + ipfsCid));
  const summaryHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(process.env.SUMMARY || "Routine inspection OK"));
  const inspectorTimestamp = Math.floor(Date.now() / 1000);
  const nonce = ethers.utils.hexlify(ethers.utils.randomBytes(32));

  const chainId = (await provider.getNetwork()).chainId;
  const rawHash = ethers.utils.solidityKeccak256(
    ["address","uint256","bytes32","bytes32","address","uint256","bytes32"],
    [contractAddress, chainId, contentHash, summaryHash, inspector, inspectorTimestamp, nonce]
  );

  const signature = await inspectorWallet.signMessage(ethers.utils.arrayify(rawHash));

  console.log("inspector:", inspector);
  console.log("contentHash:", contentHash);
  console.log("summaryHash:", summaryHash);
  console.log("inspectorTimestamp:", inspectorTimestamp);
  console.log("nonce:", nonce);
  console.log("signature:", signature);
  console.log("rawHash:", rawHash);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
