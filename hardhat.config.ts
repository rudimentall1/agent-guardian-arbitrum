import "@nomicfoundation/hardhat-toolbox";
import type { HardhatUserConfig } from "hardhat/config";
import * as dotenv from "dotenv";

dotenv.config();

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
      evmVersion: "cancun",
    },
  },

  paths: {
    sources: "./contracts",
    tests: "./contracts-test",
  },

  networks: {
    hardhat: {
      chainId: 31337,
    },

    arbitrumSepolia: {
      url: process.env.ARB_SEPOLIA_RPC || "https://sepolia-rollup.arbitrum.io/rpc",
      accounts: [
        process.env.PRIVATE_KEY,
        process.env.AGENT_PRIVATE_KEY,
        process.env.GUARDIAN_PRIVATE_KEY,
      ].filter(Boolean) as string[],
      chainId: 421614,
    },
  },
};

export default config;
