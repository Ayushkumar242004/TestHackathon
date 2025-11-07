import dotenv from "dotenv";
import { ethers } from "ethers";
import fs from "fs";

dotenv.config();

const provider = new ethers.providers.JsonRpcProvider(process.env.RPC);
const wallet = new ethers.Wallet(process.env.SUBMITTER_PK, provider);
const artifact = JSON.parse(fs.readFileSync("artifacts/contracts/Compliance.sol/Compliance.json", "utf8"));
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, artifact.abi, wallet);

async function main() {
  const certHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("certificate#1"));
  const owner = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const expiry = Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60; // 30 days

  const tx = await contract.issueCertificate(certHash, owner, expiry);
  await tx.wait();
  console.log("Certificate issued ✅", certHash);
}

main().catch(console.error);
