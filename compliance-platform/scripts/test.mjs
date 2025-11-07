import { ethers } from "ethers";

const pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // INSPECTOR_PK
const wallet = new ethers.Wallet(pk);

// use the raw hash from /debug-raw-hash
const rawHash = "0x2a3ebf9f12942672e9db1938c146f44774ec551d7270f826530592b0d87d8624";

const sig = await wallet.signMessage(ethers.utils.arrayify(rawHash));
console.log("Signature:", sig);
