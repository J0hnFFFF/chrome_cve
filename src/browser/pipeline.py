"""
CVE Reproduction Pipeline

Multi-agent based pipeline with LLM integration for Chrome CVE reproduction.
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from .config import load_config, Settings
from .intel import IntelCollector, ChromeVersionMapper, ChromeDownloader
from .memory import EpisodeMemory, SemanticMemory, LearningEngine, CVECase
from .agents import (
    OrchestratorAgent,
    AnalyzerAgent,
    GeneratorAgent,
    VerifierAgent,
    CriticAgent,
)
from .services import create_llm_service, LLMService, ToolDefinition
from .tools import (
    fetch_chromium_commit,
    fetch_chromium_file,
    search_chromium_code,
    analyze_patch_components,
    ANALYSIS_TOOLS,
)

logger = logging.getLogger(__name__)


def create_tool_definition(func, name: str = None, description: str = None) -> ToolDefinition:
    """Create a ToolDefinition from a function or SerializedTool."""
    import inspect
    from agentlib.lib.tools.tool_wrapper import SerializedTool

    # Handle SerializedTool from agentlib
    if isinstance(func, SerializedTool):
        actual_tool = func.get_tool()
        func_name = name or func.name
        func_doc = description or actual_tool.description or func_name

        # Get parameters from the tool's args_schema
        properties = {}
        required = []
        if hasattr(actual_tool, 'args_schema') and actual_tool.args_schema:
            schema = actual_tool.args_schema.schema()
            properties = schema.get("properties", {})
            required = schema.get("required", [])

        parameters = {
            "type": "object",
            "properties": properties,
            "required": required,
        }

        return ToolDefinition(
            name=func_name,
            description=func_doc,
            parameters=parameters,
            function=actual_tool.func if hasattr(actual_tool, 'func') else func,
        )

    # Handle regular functions
    func_name = name or func.__name__
    func_doc = description or (func.__doc__ or "").split("\n")[0] or func_name

    # Get parameter info
    sig = inspect.signature(func)
    hints = getattr(func, "__annotations__", {})

    properties = {}
    required = []

    for param_name, param in sig.parameters.items():
        if param_name == "self":
            continue

        param_type = hints.get(param_name, str)
        json_type = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }.get(param_type, "string")

        properties[param_name] = {
            "type": json_type,
            "description": f"Parameter: {param_name}",
        }

        if param.default == inspect.Parameter.empty:
            required.append(param_name)

    parameters = {
        "type": "object",
        "properties": properties,
        "required": required,
    }

    return ToolDefinition(
        name=func_name,
        description=func_doc,
        parameters=parameters,
        function=func,
    )


class CVEReproductionPipeline:
    """
    Multi-agent CVE reproduction pipeline with LLM integration.

    Stages:
    1. Intel Collection - Gather CVE info from multiple sources
    2. Analysis - Analyze patches with LLM-powered analyzer agent
    3. Generation - Generate PoC with LLM-powered generator agent
    4. Verification - Verify PoC with verifier agent
    5. Learning - Store case for future reference
    """

    def __init__(
        self,
        cve_id: str,
        config_path: str = None,
        output_dir: str = None,
        chrome_path: str = None,
        d8_path: str = None,
        model: str = None,
        commit: str = None,
    ):
        self.cve_id = cve_id
        self.commit = commit
        self.settings = load_config(config_path)
        self.output_dir = Path(output_dir or f"./output/{cve_id}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Override settings from CLI if provided
        if chrome_path:
            self.settings.execution.chrome_path = chrome_path
        if d8_path:
            self.settings.execution.d8_path = d8_path
        if model:
            self.settings.llm.default_model = model

        # Initialize components
        self._init_llm_service()
        self._init_memory()
        self._init_tools()
        self._init_agents()
        self._init_intel()

        # Pipeline state
        self.results: Dict[str, Any] = {
            "cve_id": cve_id,
            "start_time": datetime.now().isoformat(),
            "stages": {},
        }

    def _init_llm_service(self) -> None:
        """Initialize LLM service."""
        llm_config = {
            "default_model": self.settings.llm.default_model,
            "temperature": self.settings.llm.temperature,
            "openai_api_key": self.settings.llm.openai_api_key or os.environ.get("OPENAI_API_KEY", ""),
            "openai_base_url": self.settings.llm.openai_base_url or os.environ.get("OPENAI_BASE_URL", ""),
            "anthropic_api_key": self.settings.llm.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY", ""),
            "anthropic_base_url": self.settings.llm.anthropic_base_url or os.environ.get("ANTHROPIC_BASE_URL", ""),
        }

        # Validate keys
        if not llm_config["openai_api_key"] and not llm_config["anthropic_api_key"]:
            raise ValueError(
                "No LLM API keys found! System requires LLM configuration via environment variables.\n"
                "Please set OPENAI_API_KEY or ANTHROPIC_API_KEY."
            )

        # Determine backend based on available keys
        if llm_config.get("anthropic_api_key"):
            backend = "anthropic"
        else:
            backend = "openai"

        try:
            self.llm_service = create_llm_service(config=llm_config, backend=backend)
            logger.info(f"LLM service initialized with {backend} backend")
        except Exception as e:
            logger.warning(f"Failed to initialize LLM service: {e}")
            self.llm_service = None

    def _init_memory(self) -> None:
        """Initialize memory systems."""
        storage_base = self.settings.memory.storage_path

        self.episode_memory = EpisodeMemory(
            storage_path=f"{storage_base}/episodes"
        )
        self.semantic_memory = SemanticMemory(
            storage_path=f"{storage_base}/semantic"
        )
        self.learning_engine = LearningEngine(
            episode_memory=self.episode_memory,
            semantic_memory=self.semantic_memory,
        )

    def _init_tools(self) -> None:
        """Initialize tools for agents."""
        # Analysis tools
        self.analysis_tools = [
            create_tool_definition(
                fetch_chromium_commit,
                description="Fetch a commit diff from Chromium Git repository"
            ),
            create_tool_definition(
                fetch_chromium_file,
                description="Fetch a source file from Chromium repository at a specific commit"
            ),
            create_tool_definition(
                search_chromium_code,
                description="Search for code patterns in Chromium codebase"
            ),
        ]

        # Generation tools (subset)
        self.generation_tools = [
            create_tool_definition(
                fetch_chromium_file,
                description="Fetch source file for reference"
            ),
        ]

        logger.info(f"Initialized {len(self.analysis_tools)} analysis tools")

    def _init_agents(self) -> None:
        """Initialize agent system with LLM integration."""
        # Create agents
        self.orchestrator = OrchestratorAgent({
            "max_retries": self.settings.agents.max_retries,
        })
        self.analyzer = AnalyzerAgent()
        self.generator = GeneratorAgent()
        self.verifier = VerifierAgent({
            "chrome_path": self.settings.execution.chrome_path,
            "d8_path": self.settings.execution.d8_path,
            "timeout": self.settings.execution.timeout,
        })
        self.critic = CriticAgent()

        # Set LLM service for all agents
        if self.llm_service:
            self.orchestrator.set_llm_service(self.llm_service)
            self.analyzer.set_llm_service(self.llm_service)
            self.generator.set_llm_service(self.llm_service)
            self.verifier.set_llm_service(self.llm_service)
            self.critic.set_llm_service(self.llm_service)
            logger.info("LLM service connected to all agents")

        # Set tools for agents
        self.analyzer.set_tools(self.analysis_tools)
        self.generator.set_tools(self.generation_tools)

        # Set memory for agents
        self.analyzer.set_memory(
            semantic_memory=self.semantic_memory,
            learning_engine=self.learning_engine,
        )
        self.generator.set_memory(
            semantic_memory=self.semantic_memory,
            episode_memory=self.episode_memory,
        )

        # Set memory for orchestrator (for learning)
        self.orchestrator.set_memory(
            episode_memory=self.episode_memory,
            learning_engine=self.learning_engine,
        )

        # Register agents with orchestrator
        self.orchestrator.register_agent(self.analyzer)
        self.orchestrator.register_agent(self.generator)
        self.orchestrator.register_agent(self.verifier)
        self.orchestrator.register_agent(self.critic)

        logger.info("All agents initialized and registered")

    def _init_intel(self) -> None:
        """Initialize intel system."""
        self.intel_collector = IntelCollector(
            nvd_api_key=self.settings.intel.nvd_api_key,
            github_token=self.settings.intel.github_token,
        )
        self.version_mapper = ChromeVersionMapper()
        self.chrome_downloader = ChromeDownloader()

    def run(self) -> Dict[str, Any]:
        """
        Execute the full reproduction pipeline.

        Returns:
            Pipeline results dictionary
        """
        print(f"\n{'='*60}")
        print(f"CVE Reproduction Pipeline: {self.cve_id}")
        print(f"{'='*60}\n")

        if self.llm_service:
            print("LLM: Enabled")
        else:
            print("LLM: Disabled (rule-based fallback)")

        try:
            # Stage 1: Intel Collection
            print("\n[Stage 1] Intelligence Collection")
            cve_info = self._collect_intel()
            if not cve_info:
                return self._failure("Intel collection failed")

            # Stage 2: Environment Setup (Download or Build)
            print("\n[Stage 2] Environment Setup")
            
            # Identify target version/commit
            target_commit = self.commit
            target_version = None
            
            # If we collected intel, try to get version from it
            if cve_info and not target_commit:
                # Naive attempt to find a version (this logic would need to be more robust in prod)
                # For now, let's assume we rely on what the agents determine, 
                # but we can try to pre-fetch if we have a commit hash from patches
                if hasattr(cve_info, 'patches') and cve_info.patches:
                    target_commit = cve_info.patches[0].get('commit_hash')

            d8_path = self.settings.execution.d8_path
            chrome_path = self.settings.execution.chrome_path
            
            # Hybrid Workflow Logic
            if self.settings.build.mode in ["hybrid", "local_windows"]:
                from .tools.build_manager import WindowsBuildManager
                build_manager = WindowsBuildManager(self.settings)

                # Skip download if pure local mode
                download_success = False
                if self.settings.build.mode == "hybrid" and target_commit:
                    print(f"  [Hybrid] Attempting binary download first for {target_commit}...")
                    # Try to map commit to version for download
                    # This part is simplified; normally we map commit -> position -> download
                    # For V8 bugs, we often need d8
                    downloaded_d8 = self.chrome_downloader.download_version(target_commit) # Assuming downloader handles commit mapping or we add it
                    if downloaded_d8:
                        d8_path = downloaded_d8
                        download_success = True
                        print("  [Hybrid] Binary download successful.")
                    else:
                        print("  [Hybrid] Binary download failed or not found.")

                # Fallback to build
                if (not download_success and self.settings.build.auto_fallback) or self.settings.build.mode == "local_windows":
                    print(f"  [{self.settings.build.mode.upper()}] Triggering local build...")
                    if target_commit:
                        print(f"  Building commit: {target_commit}")
                        if build_manager.fetch_source(target="v8", version=target_commit):
                            built_d8 = build_manager.build_target(target="d8", asan=self.settings.execution.asan_enabled)
                            if built_d8:
                                d8_path = built_d8
                                print(f"  [Build] Success! d8 available at: {d8_path}")
                            else:
                                print("  [Build] Compilation failed.")
                        else:
                            print("  [Build] Source fetch failed.")
                    else:
                        print("  [Build] No specific commit identified to build. Skipping build stage.")

            # Stage 3-5: Run multi-agent pipeline
            print("\n[Stage 3-5] Multi-Agent Pipeline")
            print("  - Analysis (LLM + tools)")
            print("  - PoC Generation (LLM + templates)")
            print("  - Verification (execution + crash analysis)")

            result = self.orchestrator.run({
                "cve_id": self.cve_id,
                "cve_info": cve_info,
                "patches": cve_info.get("patches", []) if isinstance(cve_info, dict) else getattr(cve_info, "patches", []),
                "start_time": self.results["start_time"],
                "chrome_path": chrome_path,
                "d8_path": d8_path,
            })

            # Stage 5: Learning
            print("\n[Stage 5] Learning & Storage")
            self._store_case(result)

            # Finalize results
            self.results["success"] = result.get("success", False)
            self.results["analysis"] = result.get("analysis")
            self.results["poc"] = result.get("poc")
            self.results["verification"] = result.get("verification")
            self.results["attempts"] = result.get("attempts", {})
            self.results["end_time"] = datetime.now().isoformat()

            self._save_results()
            self._print_summary()

            return self.results

        except Exception as e:
            import traceback
            traceback.print_exc()
            return self._failure(str(e))

    def _collect_intel(self) -> Optional[Any]:
        """Collect intelligence for the CVE."""
        print(f"  Collecting intel for {self.cve_id}...")

        # If commit hash is provided, fetch patch directly
        if self.commit:
            print(f"  Using direct commit: {self.commit}")
            try:
                from .tools import fetch_chromium_commit
                # Handle SerializedTool wrapper
                if hasattr(fetch_chromium_commit, 'get_tool'):
                    tool = fetch_chromium_commit.get_tool()
                    patch_diff = tool.func(self.commit)
                else:
                    patch_diff = fetch_chromium_commit(self.commit)

                # Create a minimal CVEInfo-like dict
                cve_info = {
                    "cve_id": self.cve_id,
                    "description": f"Analysis based on commit {self.commit}",
                    "component": "Unknown",
                    "severity": "Unknown",
                    "cvss_score": "N/A",
                    "patches": [{
                        "commit_hash": self.commit,
                        "repository": "chromium/src",
                        "diff": patch_diff,
                    }],
                }
                print(f"  [OK] Fetched patch from commit {self.commit[:12]}...")
                self.results["stages"]["intel"] = {"success": True, "source": "direct_commit"}
                return cve_info
            except Exception as e:
                logger.error(f"Failed to fetch commit: {e}")
                return None

        try:
            cve_info = self.intel_collector.collect_and_fuse(
                self.cve_id,
                tier_limit=2,
            )
        except Exception as e:
            logger.error(f"Intel collection error: {e}")
            cve_info = None

        if cve_info:
            # Save intel to output
            intel_path = self.output_dir / "cve_info.json"
            with open(intel_path, 'w', encoding='utf-8') as f:
                json.dump(cve_info.to_dict() if hasattr(cve_info, 'to_dict') else cve_info, f, indent=2)

            if hasattr(cve_info, 'to_knowledge_text'):
                knowledge_path = self.output_dir / "cve_knowledge.md"
                with open(knowledge_path, 'w', encoding='utf-8') as f:
                    f.write(cve_info.to_knowledge_text())

            component = cve_info.component if hasattr(cve_info, 'component') else cve_info.get('component', 'Unknown')
            severity = cve_info.severity if hasattr(cve_info, 'severity') else cve_info.get('severity', 'Unknown')
            cvss = cve_info.cvss_score if hasattr(cve_info, 'cvss_score') else cve_info.get('cvss_score', 'N/A')
            patches = cve_info.patches if hasattr(cve_info, 'patches') else cve_info.get('patches', [])

            print(f"  [OK] Component: {component}")
            print(f"  [OK] Severity: {severity} (CVSS: {cvss})")
            print(f"  [OK] Patches: {len(patches)}")

            self.results["stages"]["intel"] = {
                "success": True,
                "component": component,
                "patches": len(patches),
            }

            return cve_info

        self.results["stages"]["intel"] = {"success": False}
        print("  [FAILED] Could not collect CVE information")
        return None

    def _store_case(self, result: Dict[str, Any]) -> None:
        """Store case in episode memory."""
        try:
            case = CVECase(
                cve_id=self.cve_id,
                component=result.get("analysis", {}).get("component", ""),
                vulnerability_type=result.get("analysis", {}).get("vulnerability_type", ""),
                analysis_result=result.get("analysis", {}),
                poc_result=result.get("poc", {}),
                verify_result=result.get("verification", {}),
                success=result.get("success", False),
            )

            if result.get("success"):
                case.successful_strategy = result.get("analysis", {}).get("poc_strategy", "")
                case.key_insights = [
                    f"Vulnerability type: {case.vulnerability_type}",
                    f"Component: {case.component}",
                ]

            self.learning_engine.learn_from_case(case)
            print("  [OK] Case stored in episode memory")
        except Exception as e:
            logger.warning(f"Failed to store case: {e}")

    def _failure(self, error: str) -> Dict[str, Any]:
        """Create failure result."""
        self.results["success"] = False
        self.results["error"] = error
        self.results["end_time"] = datetime.now().isoformat()
        self._save_results()
        return self.results

    def _save_results(self) -> None:
        """Save results to file."""
        results_path = self.output_dir / "results.json"
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)

        # Save PoC if generated
        poc = self.results.get("poc", {})
        if poc and poc.get("code"):
            ext = ".html" if poc.get("language") == "html" else ".js"
            poc_path = self.output_dir / f"poc{ext}"
            with open(poc_path, 'w', encoding='utf-8') as f:
                f.write(poc["code"])
            print(f"  [OK] PoC saved to {poc_path}")

    def _print_summary(self) -> None:
        """Print pipeline summary."""
        print(f"\n{'='*60}")
        print("Pipeline Summary")
        print(f"{'='*60}")
        print(f"CVE: {self.cve_id}")
        print(f"Success: {self.results.get('success', False)}")
        print(f"Output: {self.output_dir}")

        if self.results.get("analysis"):
            analysis = self.results["analysis"]
            print(f"\nAnalysis:")
            print(f"  Component: {analysis.get('component', 'N/A')}")
            print(f"  Vuln Type: {analysis.get('vulnerability_type', 'N/A')}")
            print(f"  Confidence: {analysis.get('confidence', 'N/A')}")

        if self.results.get("verification"):
            verify = self.results["verification"]
            print(f"\nVerification:")
            print(f"  Crash: {verify.get('crash_detected', False)}")
            print(f"  Reproducibility: {verify.get('reproducibility', 'N/A')}")

        if self.results.get("attempts"):
            attempts = self.results["attempts"]
            print(f"\nAttempts:")
            for stage, count in attempts.items():
                print(f"  {stage}: {count}")
