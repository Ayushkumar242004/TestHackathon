// scripts/verifyInspection.js (ESM)
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

  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (!contractAddress) throw new Error("Set CONTRACT_ADDRESS in .env");

  const artifactPath = path.join(__dirname, "../artifacts/contracts/Compliance.sol/Compliance.json");
  if (!fs.existsSync(artifactPath)) {
    throw new Error(`Artifact not found at ${artifactPath}. Run npx hardhat compile`);
  }
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const abi = artifact.abi;

  const contract = new ethers.Contract(contractAddress, abi, provider);

  const contentHash = process.env.CONTENT_HASH;
  if (!contentHash) console.warn("CONTENT_HASH not set in .env — some checks will be skipped.");

  const txHash = process.env.TX_HASH; // optional: pass tx hash to inspect receipt
  if (txHash) {
    console.log("Fetching receipt for tx:", txHash);
    const receipt = await provider.getTransactionReceipt(txHash);
    if (!receipt) {
      console.log("Receipt not found for tx (maybe not mined).");
    } else {
      console.log("Receipt status:", receipt.status, "logs length:", receipt.logs.length);
      console.log("Raw logs:");
      console.log(receipt.logs);

      // Attempt to decode each log using contract.interface
      console.log("\nAttempting to decode logs with ABI...");
      for (const rawLog of receipt.logs) {
        try {
          const parsed = contract.interface.parseLog(rawLog);
          console.log("Decoded event:", parsed.name, parsed.args);
        } catch (err) {
          // not from this contract ABI (or topics don't match)
          // print topic0 so we can compare
          console.log("Could not decode log with this ABI. topic0:", rawLog.topics[0]);
        }
      }
    }
  } else {
    console.log("TX_HASH not provided. Skipping receipt inspection.");
  }

  // Check seenInspections mapping if contentHash provided
  if (contentHash) {
    console.log("\nChecking seenInspections for contentHash:", contentHash);
    try {
      const seen = await contract.seenInspections(contentHash);
      console.log("seenInspections:", seen);
    } catch (err) {
      console.error("Error calling seenInspections:", err.message || err);
    }
  }

  // Query indexed InspectionRecorded events for this contentHash (safer)
  try {
    if (contentHash) {
      const filter = contract.filters.InspectionRecorded(contentHash, null, null, null);
      const logs = await contract.queryFilter(filter, 0, "latest");
      console.log(`\nFound ${logs.length} InspectionRecorded event(s) for contentHash:`);
      logs.forEach((l, i) => {
        console.log(`#${i}: inspector=${l.args.inspector}, ts=${l.args.ts.toNumber()}, summaryHash=${l.args.summaryHash}, meta=${l.args.meta}`);
      });
    } else {
      console.log("\nCONTENT_HASH not provided — querying recent InspectionRecorded events (last 1000 blocks)");
      const events = await contract.queryFilter(contract.filters.InspectionRecorded(), "latest" - 1000, "latest");
      console.log("Recent InspectionRecorded events (decoded):", events.map(e => ({contentHash: e.args.contentHash, inspector: e.args.inspector, ts: e.args.ts.toNumber()})));
    }
  } catch (err) {
    console.error("Error querying events:", err.message || err);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
