
## [2026-06-25 22:48] Flash loan price manipulation in AMM spot price oracle
- **Pattern**: FLA-003 — flash_loan/price_manipulation
- **Severity**: Critical
- **Protocol**: UniswapV3Oracle
- **Net profit**: $145,000
- **KG entry**: added `FLA-003` with 3 detection regexes
- **Hypothesis**: IF flash_loan vulnerability exists in PriceOracle.sol:88 THEN attacker can drain reserves BECAUSE slot0() is read in same tx as swap execution
- **Regexes**: ['flashLoan', 'executeOperation', 'uniswapV3Flash']

