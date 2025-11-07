// scripts/deploy.mjs (ESM) — deploy using ethers + compiled artifact
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import { ethers } from "ethers";

dotenv.config();

async function main() {
  const rpc = process.env.RPC || "http://127.0.0.1:8545";
  const provider = new ethers.providers.JsonRpcProvider(rpc);

  const deployerPk = process.env.DEPLOYER_PK;
  if (!deployerPk) {
    console.error("Missing DEPLOYER_PK in .env. Start `npx hardhat node` and copy a private key.");
    process.exit(1);
  }
  const wallet = new ethers.Wallet(deployerPk, provider);
  console.log("Deploying from:", wallet.address);

  // Path to Hardhat artifact
  const artifactPath = path.join(process.cwd(), "artifacts", "contracts", "Compliance.sol", "Compliance.json");
  if (!fs.existsSync(artifactPath)) {
    console.error("Artifact not found at", artifactPath);
    console.error("Run: npx hardhat compile");
    process.exit(1);
  }

  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const abi = artifact.abi;
  const bytecode = artifact.bytecode;

  const factory = new ethers.ContractFactory(abi, bytecode, wallet);

  // Constructor takes admin address in your contract
  const adminAddress = wallet.address;

  console.log("Sending deploy transaction...");
  const contract = await factory.deploy(adminAddress);
  console.log("txHash:", contract.deployTransaction.hash);
  await contract.deployTransaction.wait(); // wait for mining

  console.log("Deployed Compliance at:", contract.address);
  console.log("Transaction confirmed in block:", (await provider.getTransactionReceipt(contract.deployTransaction.hash)).blockNumber);
  // Optionally update .env or print full details
  console.log("\nAdd this to your .env:");
  console.log(`CONTRACT_ADDRESS=${contract.address}`);
}

main().catch((err) => {
  console.error("Deploy failed:", err);
  process.exitCode = 1;
});
