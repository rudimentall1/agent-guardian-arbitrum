// Standalone compiler using the npm `solc` package instead of Hardhat's
// built-in downloader. Hardhat's downloader fetches compiler binaries from
// binaries.soliditylang.org, which is not reachable from this sandbox's
// network egress allowlist. This script produces artifacts in the same
// shape Hardhat/ethers expect (abi + bytecode + linkReferences) so tests
// can load contracts without depending on Hardhat's compile task.
//
// This is a sandbox workaround only — it is not meant to replace
// `hardhat compile` / `forge build` in a normal developer or CI
// environment with unrestricted network access. See docs/protocol-spec.md
// for the record of this constraint.
const fs = require("fs");
const path = require("path");
const solc = require("solc");

const ROOT = path.resolve(__dirname, "..");
const CONTRACTS_DIR = path.join(ROOT, "contracts");
const ARTIFACTS_DIR = path.join(ROOT, "artifacts");

function findSolFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...findSolFiles(full));
    else if (entry.name.endsWith(".sol")) out.push(full);
  }
  return out;
}

function importCallback(importPath) {
  // Resolve node_modules imports (e.g. @openzeppelin/contracts/...)
  const candidates = [
    path.join(ROOT, "node_modules", importPath),
    path.join(ROOT, importPath),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      return { contents: fs.readFileSync(c, "utf8") };
    }
  }
  return { error: `File not found: ${importPath}` };
}

const solFiles = findSolFiles(CONTRACTS_DIR);
const sources = {};
for (const f of solFiles) {
  const rel = path.relative(ROOT, f);
  sources[rel] = { content: fs.readFileSync(f, "utf8") };
}

const input = {
  language: "Solidity",
  sources,
  settings: {
    optimizer: { enabled: true, runs: 200 },
    viaIR: true,
    evmVersion: "cancun",
    outputSelection: {
      "*": {
        "*": [
          "abi",
          "evm.bytecode.object",
          "evm.deployedBytecode.object",
          "evm.bytecode.linkReferences",
          "evm.deployedBytecode.linkReferences",
          "metadata",
        ],
      },
    },
  },
};

const output = JSON.parse(solc.compile(JSON.stringify(input), { import: importCallback }));

let hasError = false;
if (output.errors) {
  for (const err of output.errors) {
    console.log(err.formattedMessage || err.message);
    if (err.severity === "error") hasError = true;
  }
}
if (hasError) {
  process.exit(1);
}

for (const [file, contracts] of Object.entries(output.contracts)) {
  for (const [name, contract] of Object.entries(contracts)) {
    const outDir = path.join(ARTIFACTS_DIR, file);
    fs.mkdirSync(outDir, { recursive: true });
    const artifact = {
      _format: "hh-sol-artifact-1",
      contractName: name,
      sourceName: file,
      abi: contract.abi,
      bytecode: "0x" + contract.evm.bytecode.object,
      deployedBytecode: "0x" + contract.evm.deployedBytecode.object,
      linkReferences: contract.evm.bytecode.linkReferences ?? {},
      deployedLinkReferences: contract.evm.deployedBytecode.linkReferences ?? {},
    };
    fs.writeFileSync(path.join(outDir, `${name}.json`), JSON.stringify(artifact, null, 2));
  }
}

console.log(`Compiled ${solFiles.length} file(s) -> ${ARTIFACTS_DIR}`);
