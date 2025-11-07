import dotenv from "dotenv";
import { ethers } from "ethers";
import fs from "fs";

dotenv.config();

const provider = new ethers.providers.JsonRpcProvider(process.env.RPC);
const wallet = new ethers.Wallet(process.env.DEPLOYER_PK, provider);
const artifact = JSON.parse(fs.readFileSync("artifacts/contracts/Compliance.sol/Compliance.json", "utf8"));
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, artifact.abi, wallet);

async function main() {
  const SUBMITTER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"; // example
  const INSPECTOR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const AGENT = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";

  const SUBMITTER_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("SUBMITTER_ROLE"));
  const INSPECTOR_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("INSPECTOR_ROLE"));
  const AGENT_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("AGENT_ROLE"));

  console.log("Granting roles...");
  await contract.grantRole(SUBMITTER_ROLE, SUBMITTER);
  await contract.grantRole(INSPECTOR_ROLE, INSPECTOR);
  await contract.grantRole(AGENT_ROLE, AGENT);
  console.log("Roles granted successfully ✅");
}

main().catch(console.error);
