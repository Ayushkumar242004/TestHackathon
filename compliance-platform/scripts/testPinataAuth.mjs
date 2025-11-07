// scripts/testPinataAuth.mjs
import axios from "axios";
import dotenv from "dotenv";
dotenv.config();

async function main() {
  try {
    const headers = {};
    if (process.env.PINATA_JWT) {
      headers.Authorization = `Bearer ${process.env.PINATA_JWT}`;
    } else if (process.env.PINATA_API_KEY && process.env.PINATA_API_SECRET) {
      headers.pinata_api_key = process.env.PINATA_API_KEY;
      headers.pinata_secret_api_key = process.env.PINATA_API_SECRET;
    } else {
      console.error("No Pinata credentials in .env (PINATA_JWT or PINATA_API_KEY+PINATA_API_SECRET).");
      process.exit(1);
    }

    const resp = await axios.get("https://api.pinata.cloud/data/testAuthentication", { headers, timeout: 10000 });
    console.log("Pinata auth OK:", resp.data);
  } catch (err) {
    console.error("Pinata auth failed.");
    if (err.response) {
      console.error("Status:", err.response.status);
      console.error("Body:", JSON.stringify(err.response.data, null, 2));
    } else {
      console.error(err.message);
    }
    process.exitCode = 1;
  }
}

main();
