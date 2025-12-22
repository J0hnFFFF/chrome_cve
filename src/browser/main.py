"""
Browser CVE Reproduction Framework

Usage:
    python main.py --cve CVE-2024-XXXX [--chrome-version VERSION] [--output-dir DIR]
"""

import argparse
import os
import sys
import json
from datetime import datetime
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment
if not os.environ.get('ENV_PATH'):
    load_dotenv()
else:
    load_dotenv(dotenv_path=os.environ['ENV_PATH'])

from browser.data import ChromiumCVEProcessor
from browser.agents import PatchAnalyzer, PoCGenerator, CrashVerifier
from browser.tools import download_chrome_version, find_chrome_executable, create_poc_file


class BrowserCVEReproducer:
    """
    Main orchestrator for browser CVE reproduction.

    Pipeline:
    1. Information Collection - Gather CVE info, patches from NVD/Chromium
    2. Patch Analysis - Analyze patches to understand vulnerability
    3. PoC Generation - Generate HTML/JS PoC with iterative testing
    4. Verification - Verify crash reproducibility
    """

    def __init__(self, cve_id: str, chrome_version: str = None, output_dir: str = None):
        self.cve_id = cve_id
        self.chrome_version = chrome_version
        self.output_dir = output_dir or f"./output/{cve_id}"
        self.chrome_path = None

        self.results = {
            "cve_id": cve_id,
            "start_time": datetime.now().isoformat(),
            "stages": {},
            "success": False,
            "total_cost": 0.0,
        }

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

    def stage_info_collection(self) -> bool:
        """Stage 1: Collect CVE information."""
        print("\n" + "="*60)
        print("Stage 1: Information Collection")
        print("="*60 + "\n")

        try:
            processor = ChromiumCVEProcessor(self.cve_id)
            self.cve_info = processor.process()
            self.cve_knowledge = processor.to_knowledge_text()

            # Save CVE info
            info_path = os.path.join(self.output_dir, "cve_info.json")
            with open(info_path, 'w') as f:
                json.dump(self.cve_info.to_dict(), f, indent=2)

            knowledge_path = os.path.join(self.output_dir, "cve_knowledge.md")
            with open(knowledge_path, 'w') as f:
                f.write(self.cve_knowledge)

            print(f"Component: {self.cve_info.component}")
            print(f"Severity: {self.cve_info.severity} (CVSS: {self.cve_info.cvss_score})")
            print(f"Patches found: {len(self.cve_info.patches)}")

            self.results["stages"]["info_collection"] = {
                "success": True,
                "component": self.cve_info.component,
                "patches": len(self.cve_info.patches),
            }

            if not self.cve_info.patches:
                print("WARNING: No patches found. Analysis may be limited.")

            return True

        except Exception as e:
            print(f"ERROR: {e}")
            self.results["stages"]["info_collection"] = {
                "success": False,
                "error": str(e),
            }
            return False

    def stage_patch_analysis(self) -> bool:
        """Stage 2: Analyze patches to understand vulnerability."""
        print("\n" + "="*60)
        print("Stage 2: Patch Analysis")
        print("="*60 + "\n")

        if not self.cve_info.patches:
            print("No patches to analyze.")
            self.results["stages"]["patch_analysis"] = {
                "success": False,
                "error": "No patches available",
            }
            return False

        try:
            # Get patch diff
            patch_diff = ""
            for patch in self.cve_info.patches:
                if patch.diff_content:
                    patch_diff += f"\n\n# Patch: {patch.commit_hash}\n"
                    patch_diff += patch.diff_content

            if not patch_diff:
                print("No patch diff content available.")
                return False

            # Run patch analyzer
            analyzer = PatchAnalyzer(
                cve_id=self.cve_id,
                cve_knowledge=self.cve_knowledge,
                patch_diff=patch_diff,
            )

            print("Analyzing patches...")
            result = analyzer.invoke()
            self.vulnerability_analysis = result.value

            # Save analysis
            analysis_path = os.path.join(self.output_dir, "vulnerability_analysis.json")
            with open(analysis_path, 'w') as f:
                json.dump(self.vulnerability_analysis, f, indent=2)

            print(f"\nVulnerability Type: {self.vulnerability_analysis.get('vulnerability_type', 'Unknown')}")
            print(f"Component: {self.vulnerability_analysis.get('component', 'Unknown')}")

            self.results["stages"]["patch_analysis"] = {
                "success": True,
                "vulnerability_type": self.vulnerability_analysis.get('vulnerability_type'),
                "cost": analyzer.get_cost(),
            }
            self.results["total_cost"] += analyzer.get_cost()

            return True

        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()
            self.results["stages"]["patch_analysis"] = {
                "success": False,
                "error": str(e),
            }
            return False

    def stage_setup_chrome(self) -> bool:
        """Setup Chrome for testing."""
        print("\n" + "="*60)
        print("Stage: Chrome Setup")
        print("="*60 + "\n")

        try:
            # Determine Chrome version to use
            version = self.chrome_version
            if not version:
                # Try to extract from affected versions
                if self.cve_info.affected_versions:
                    version = self.cve_info.affected_versions[0]
                else:
                    version = "stable"  # Default to stable

            print(f"Setting up Chrome version: {version}")

            chrome_dir = os.path.join(self.output_dir, "chrome")

            # Try to download Chrome
            result = download_chrome_version.func(version, "linux64", chrome_dir)
            print(result)

            # Find Chrome executable
            find_result = find_chrome_executable.func(chrome_dir)
            if "Found Chrome:" in find_result:
                self.chrome_path = find_result.split(": ")[1]
                print(f"Chrome ready: {self.chrome_path}")
                return True
            else:
                print("Could not find Chrome executable.")
                print("Please download Chrome manually and set --chrome-path")
                return False

        except Exception as e:
            print(f"Chrome setup failed: {e}")
            print("Continuing without Chrome (PoC generation only)...")
            return False

    def stage_poc_generation(self) -> bool:
        """Stage 3: Generate PoC."""
        print("\n" + "="*60)
        print("Stage 3: PoC Generation")
        print("="*60 + "\n")

        if not hasattr(self, 'vulnerability_analysis'):
            print("No vulnerability analysis available.")
            return False

        try:
            # Get patch diff for reference
            patch_diff = ""
            for patch in self.cve_info.patches:
                if patch.diff_content:
                    patch_diff += patch.diff_content[:5000]  # Limit size

            generator = PoCGenerator(
                cve_id=self.cve_id,
                vulnerability_analysis=self.vulnerability_analysis,
                patch_diff=patch_diff,
                chrome_path=self.chrome_path,
            )

            print("Generating PoC...")
            result = generator.invoke()
            self.poc_result = result.value

            # Save PoC
            if self.poc_result.get('poc_code'):
                poc_path = os.path.join(self.output_dir, "poc.html")
                with open(poc_path, 'w') as f:
                    f.write(self.poc_result['poc_code'])
                self.poc_path = poc_path
                print(f"PoC saved to: {poc_path}")

            poc_info_path = os.path.join(self.output_dir, "poc_info.json")
            with open(poc_info_path, 'w') as f:
                json.dump(self.poc_result, f, indent=2)

            success = self.poc_result.get('success', '').lower() == 'yes'
            print(f"\nPoC Generation: {'Success' if success else 'Failed'}")

            self.results["stages"]["poc_generation"] = {
                "success": success,
                "poc_type": self.poc_result.get('poc_type'),
                "cost": generator.get_cost(),
            }
            self.results["total_cost"] += generator.get_cost()

            return success

        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()
            self.results["stages"]["poc_generation"] = {
                "success": False,
                "error": str(e),
            }
            return False

    def stage_verification(self) -> bool:
        """Stage 4: Verify PoC."""
        print("\n" + "="*60)
        print("Stage 4: Verification")
        print("="*60 + "\n")

        if not hasattr(self, 'poc_result') or not self.poc_result.get('poc_code'):
            print("No PoC to verify.")
            return False

        if not self.chrome_path:
            print("No Chrome available for verification.")
            print("Please run verification manually with the generated PoC.")
            return False

        try:
            verifier = CrashVerifier(
                cve_id=self.cve_id,
                poc_code=self.poc_result.get('poc_code'),
                poc_path=self.poc_path,
                chrome_path=self.chrome_path,
                expected_behavior=self.poc_result.get('expected_behavior'),
            )

            print("Verifying PoC...")
            result = verifier.invoke()
            self.verification_result = result.value

            # Save verification result
            verify_path = os.path.join(self.output_dir, "verification.json")
            with open(verify_path, 'w') as f:
                json.dump(self.verification_result, f, indent=2)

            verified = self.verification_result.get('verified', '').lower() == 'yes'
            print(f"\nVerification: {'PASSED' if verified else 'FAILED'}")
            print(f"Crash Type: {self.verification_result.get('crash_type', 'N/A')}")
            print(f"Reproducibility: {self.verification_result.get('reproducibility', 'N/A')}")

            self.results["stages"]["verification"] = {
                "success": verified,
                "crash_type": self.verification_result.get('crash_type'),
                "reproducibility": self.verification_result.get('reproducibility'),
                "cost": verifier.get_cost(),
            }
            self.results["total_cost"] += verifier.get_cost()
            self.results["success"] = verified

            return verified

        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()
            self.results["stages"]["verification"] = {
                "success": False,
                "error": str(e),
            }
            return False

    def run(self) -> dict:
        """Execute the full reproduction pipeline."""
        print("\n" + "#"*60)
        print(f"# Browser CVE Reproduction: {self.cve_id}")
        print("#"*60)

        # Stage 1: Information Collection
        if not self.stage_info_collection():
            print("\nPipeline stopped: Information collection failed.")
            self.save_results()
            return self.results

        # Stage 2: Patch Analysis
        if not self.stage_patch_analysis():
            print("\nPipeline stopped: Patch analysis failed.")
            self.save_results()
            return self.results

        # Chrome Setup (optional)
        self.stage_setup_chrome()

        # Stage 3: PoC Generation
        self.stage_poc_generation()

        # Stage 4: Verification (only if PoC was generated and Chrome is available)
        if hasattr(self, 'poc_path') and self.chrome_path:
            self.stage_verification()

        self.results["end_time"] = datetime.now().isoformat()
        self.save_results()

        # Summary
        print("\n" + "="*60)
        print("Summary")
        print("="*60)
        print(f"CVE: {self.cve_id}")
        print(f"Success: {self.results['success']}")
        print(f"Total Cost: ${self.results['total_cost']:.4f}")
        print(f"Output: {self.output_dir}")

        return self.results

    def save_results(self):
        """Save results to file."""
        results_path = os.path.join(self.output_dir, "results.json")
        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Browser CVE Reproduction")
    parser.add_argument(
        "--cve",
        type=str,
        required=True,
        help="CVE ID (e.g., CVE-2024-1234)"
    )
    parser.add_argument(
        "--chrome-version",
        type=str,
        default=None,
        help="Chrome version to use (default: auto-detect)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory (default: ./output/<CVE-ID>)"
    )
    args = parser.parse_args()

    reproducer = BrowserCVEReproducer(
        cve_id=args.cve,
        chrome_version=args.chrome_version,
        output_dir=args.output_dir,
    )

    results = reproducer.run()

    # Exit with appropriate code
    sys.exit(0 if results.get("success") else 1)


if __name__ == "__main__":
    main()
