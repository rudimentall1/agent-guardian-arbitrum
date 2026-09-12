# Run this from the ROOT of your agent-guardian-arbitrum repo, with this
# script's folder (gate8-files) extracted somewhere accessible.
# Overwrites only the 7 files touched by this fix — nothing else.

$SourceDir = $PSScriptRoot

$files = @(
  "contracts/AgentExecutionGuard.sol",
  "contracts/AgentSmartWallet.sol",
  "contracts-test/AgentExecutionGuard.gate4b.test.ts",
  ".github/workflows/ci.yml",
  "README.md",
  "docs/hackathon/submission.md",
  "docs/hackathon/FINAL_CHECKLIST.md"
)

foreach ($f in $files) {
  $src = Join-Path $SourceDir $f
  $dst = $f
  $dstDir = Split-Path $dst -Parent
  if ($dstDir -and -not (Test-Path $dstDir)) {
    New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
  }
  Copy-Item -Force $src $dst
  Write-Host "copied: $f"
}

Write-Host ""
Write-Host "Done. Now run:"
Write-Host "  npx hardhat compile"
Write-Host "  npm test"
Write-Host "Expected: 178 passing"
