/**
 * Real, live tests for PackageGuard's core safety-check logic.
 * These hit real public data sources (npm registry, PyPI, OSV.dev) —
 * no mocking — so they double as a demo of what a buyer agent gets back.
 *
 * Run: node test.js
 */
const assert = require("assert");
const { runSafetyCheck, typosquatRisk } = require("./server.js");

async function main() {
  let passed = 0;
  let failed = 0;

  function check(label, cond) {
    if (cond) {
      console.log(`  PASS  ${label}`);
      passed++;
    } else {
      console.log(`  FAIL  ${label}`);
      failed++;
    }
  }

  console.log("\n1. A real, well-known, safe package (npm: express)");
  const express = await runSafetyCheck("npm", "express");
  check("registry lookup succeeded", express.evidence.registry.exists === true);
  check("verdict is safe or caution (not unsafe)", express.verdict !== "unsafe");
  console.log("   verdict:", express.verdict, " score:", express.safetyScore, " flags:", express.flags);

  console.log("\n2. A classic typosquat pattern (npm: reqeust, missing letter from 'request')");
  const typo = await runSafetyCheck("npm", "reqeust");
  check("flags typosquat risk", typo.flags.some((f) => f.startsWith("possible_typosquat_of")));
  console.log("   verdict:", typo.verdict, " score:", typo.safetyScore, " flags:", typo.flags);

  console.log("\n3. A package that does not exist (should be flagged unsafe)");
  const fake = await runSafetyCheck("npm", "this-package-definitely-does-not-exist-xyz-987");
  check("flags nonexistent package", fake.flags.includes("package_does_not_exist_in_registry"));
  check("verdict is unsafe", fake.verdict === "unsafe");
  console.log("   verdict:", fake.verdict, " score:", fake.safetyScore, " flags:", fake.flags);

  console.log("\n4. PyPI typosquat + nonexistent combined (reqeusts vs requests)");
  const pypiTypo = await runSafetyCheck("pypi", "reqeusts");
  check("flags both nonexistent and typosquat", pypiTypo.flags.length >= 2);
  console.log("   verdict:", pypiTypo.verdict, " score:", pypiTypo.safetyScore, " flags:", pypiTypo.flags);

  console.log("\n5. Typosquat detector unit check (exact match to a popular name is NOT a typosquat)");
  const exactMatch = typosquatRisk("requests", "pypi");
  check("exact match to popular package is not flagged risky", exactMatch.risky === false);

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
