#!/usr/bin/env bash
# run.sh — produce the full mcp-turnstile report card. No dependencies beyond python3.
set -euo pipefail
cd "$(dirname "$0")"

echo
echo "############################################################"
echo "#  mcp-turnstile — MCP server report card                  #"
echo "#  (all servers are local subprocesses; no network access) #"
echo "############################################################"

echo
echo ">>> [1/4] TOKEN TAX: what the tool catalog costs your context"
python3 -m bench.token_tax

echo
echo ">>> [2/4] METADATA TRUST: concealment / poisoning / rug-pull checks"
python3 -m bench.security_proof

echo
echo ">>> [3/4] UNICODE FORENSICS LAB: 5 concealment techniques vs i18n corpus"
python3 -m bench.concealment_lab

echo
echo ">>> [4/4] ONE BOUNDARY, BOTH FIXES: progressive disclosure"
python3 -m bench.progressive_demo

echo
echo ">>> done."
echo "    Citeable write-up : report/BENCHMARK.md"
echo "    Gap analysis      : report/GAP_ANALYSIS.md"
echo "    Machine-readable  : report/token_tax.json"
