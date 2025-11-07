// scripts/submitInspection.js (ESM - overwrite your existing file)
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { ethers } from "ethers";
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const rpc = process.env.RPC || "http://127.0.0.1:8545";
  const provider = new ethers.providers.JsonRpcProvider(rpc);

  const submitterPk = process.env.SUBMITTER_PK;
  if (!submitterPk) throw new Error("Set SUBMITTER_PK in .env (Hardhat private key)");
  const submitter = new ethers.Wallet(submitterPk, provider);

  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (!contractAddress) throw new Error("Set CONTRACT_ADDRESS in .env");

  // Load the artifact produced by Hardhat and extract the ABI
  const artifactPath = path.join(__dirname, "../artifacts/contracts/Compliance.sol/Compliance.json");
  if (!fs.existsSync(artifactPath)) {
    throw new Error(`Artifact not found at ${artifactPath}. Run npx hardhat compile`);
  }
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const abi = artifact.abi;

  const contract = new ethers.Contract(contractAddress, abi, submitter);

  // Values: prefer .env but fall back to the sample values you produced earlier
  const contentHash = process.env.CONTENT_HASH || "0x7e68368e55c5dfb5b8fc43834a308f3bd02011d38f05349a4871794556069952";
  const summaryHash = process.env.SUMMARY_HASH || "0xeee0905435240fc9bfd5e4b2a617c4905d2b35d3ca06b81f4502f7e5e4396e31";
  const inspector = process.env.INSPECTOR_ADDRESS || "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const inspectorTimestamp = parseInt(process.env.INSPECTOR_TIMESTAMP || `${Math.floor(Date.now()/1000)}`);
  const nonce = process.env.NONCE || "0xc2c2c363156f9aa6cf24f44157abd60508d401b2eb64999b48f096342d68cc65";
  const signature = process.env.SIGNATURE || "0x8c99c20d483b18feed7da16d00b271ef5ed2427b4ae5433f8b811ad3d140749408445052213408d1a2059822bdf83a078eb6c3ae4c5ea09924497548e47e3cbf1c";

  console.log("Submitting inspection with:");
  console.log({ contractAddress, submitter: submitter.address, inspector, contentHash, inspectorTimestamp, nonce });

  const tx = await contract.recordInspectionWithSignature(
    contentHash, summaryHash, inspector, inspectorTimestamp, nonce, signature, "0x"
  );
  console.log("tx.hash:", tx.hash);

  const receipt = await tx.wait();
  console.log("tx mined. status:", receipt.status);

  // Find and print InspectionRecorded event(s) from the receipt
  if (receipt.events && receipt.events.length) {
    console.log("Events from receipt:");
    for (const e of receipt.events) {
      // decode only if event matches name
      if (e.event === "InspectionRecorded") {
        console.log({
          contentHash: e.args.contentHash,
          summaryHash: e.args.summaryHash,
          inspector: e.args.inspector,
          ts: e.args.ts.toNumber(),
          meta: e.args.meta
        });
      }
    }
  } else {
    console.log("No events found in receipt (unexpected).");
  }
}

main().catch((err) => {
  console.error("ERROR:", err.message || err);
  process.exitCode = 1;
});
