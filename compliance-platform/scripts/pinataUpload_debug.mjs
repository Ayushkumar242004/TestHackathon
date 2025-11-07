// scripts/pinataUpload_debug.mjs
import fs from "fs";
import path from "path";
import FormData from "form-data";
import axios from "axios";
import dotenv from "dotenv";
dotenv.config();

const PINATA_API_BASE = "https://api.pinata.cloud";

function getAuthHeaders() {
  if (process.env.PINATA_JWT) {
    return { Authorization: `Bearer ${process.env.PINATA_JWT}` };
  }
  if (process.env.PINATA_API_KEY && process.env.PINATA_API_SECRET) {
    // Pinata accepts these as headers
    return {
      pinata_api_key: process.env.PINATA_API_KEY,
      pinata_secret_api_key: process.env.PINATA_API_SECRET
    };
  }
  throw new Error("Pinata credentials missing. Set PINATA_JWT or PINATA_API_KEY + PINATA_API_SECRET in .env");
}

async function uploadFile(filepath) {
  const absolute = path.resolve(filepath);
  if (!fs.existsSync(absolute)) {
    throw new Error(`File not found: ${absolute}`);
  }

  const form = new FormData();
  form.append("file", fs.createReadStream(absolute));
  form.append("pinataMetadata", JSON.stringify({ name: path.basename(absolute) }));

  const headers = { ...form.getHeaders(), ...getAuthHeaders() };
  console.log("Uploading file:", absolute);
  console.log("Using headers keys:", Object.keys(headers).filter(k => k.toLowerCase().includes("pinata") || k.toLowerCase().includes("authorization")));

  try {
    const resp = await axios.post(`${PINATA_API_BASE}/pinning/pinFileToIPFS`, form, {
      headers,
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 60000
    });
    console.log("Upload successful:", resp.data);
    return resp.data;
  } catch (err) {
    console.error("Upload failed.");
    if (err.response) {
      console.error("Status:", err.response.status);
      console.error("Body:", JSON.stringify(err.response.data, null, 2));
    } else {
      console.error("Error message:", err.message);
    }
    throw err;
  }
}

// CLI: node scripts/pinataUpload_debug.mjs ./image.png
if (process.argv.length < 3) {
  console.error("Usage: node scripts/pinataUpload_debug.mjs <path-to-file>");
  process.exit(1);
}

const file = process.argv[2];
uploadFile(file).catch(e => process.exitCode = 1);
