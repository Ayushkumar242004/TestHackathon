// scripts/checkCode.js (ESM)
import dotenv from "dotenv";
import { ethers } from "ethers";
dotenv.config();

async function main(){
  const provider = new ethers.providers.JsonRpcProvider(process.env.RPC || "http://127.0.0.1:8545");
  const addr = process.env.CONTRACT_ADDRESS;
  if(!addr){ console.error("Set CONTRACT_ADDRESS in .env"); process.exit(1); }
  const code = await provider.getCode(addr);
  console.log("code at", addr, "length:", code.length, " => startsWith 0x?", code.slice(0,6));
  if(code === "0x") console.log("No contract deployed at that address on this RPC.");
  else console.log("Contract bytecode present. OK.");
  console.log("chainId:", (await provider.getNetwork()).chainId);
}
main().catch(err=>{ console.error(err); process.exit(1); });
