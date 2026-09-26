import asyncio
from backend.pipeline import SecurityPipeline
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

src = """
pragma solidity ^0.8.0;
contract MultiBug {
    address public owner;
    function exploit() public {
        (bool s, ) = msg.sender.call("");
        require(tx.origin == owner);
    }
}
"""

analyzer = SolidityStaticAnalyzer()
raw = analyzer.analyze(src, "MultiBug.sol")
print("RAW FINDINGS COUNT:", len(raw))
for f in raw:
    print(f"  - {f.category} ({f.swc_id}) in {f.function} lines {f.line_start}-{f.line_end}")

async def run_pipeline():
    pipeline = SecurityPipeline()
    report = await pipeline.scan(src, "MultiBug.sol", mode="A")
    print("PIPELINE TOTAL FINDINGS:", report.total_findings)
    for f in report.findings:
        print(f"  - {f.vulnerability} (status={f.verification_status}, is_vuln={f.is_vulnerable})")

asyncio.run(run_pipeline())
