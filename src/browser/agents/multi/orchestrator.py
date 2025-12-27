"""
Orchestrator Agent

Coordinates the CVE reproduction pipeline.
Manages task flow, agent communication, retry logic, and learning.
"""

import logging
from typing import Dict, Any, List, Optional, TYPE_CHECKING

from .base import BaseReproAgent, AgentMessage, AgentState
from ...models.cve import CVEInfo
from ...config import get_settings

if TYPE_CHECKING:
    from ...services.llm_service import LLMService
    from ...memory import EpisodeMemory, LearningEngine

logger = logging.getLogger(__name__)


class OrchestratorAgent(BaseReproAgent):
    """
    Orchestrator agent for pipeline coordination.

    Responsibilities:
    - Pipeline flow control
    - Agent coordination with LLM integration
    - Retry management with learning
    - Result aggregation
    - Failure-based learning

    Uses:
    - LLMService for all sub-agents
    - LearningEngine for failure learning
    - CriticAgent for review and retry decisions
    """

    name = "orchestrator"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.agents: Dict[str, BaseReproAgent] = {}
        self.pipeline_state: Dict[str, Any] = {}
        self.max_retries = config.get("max_retries", 3) if config else 3

        # Learning integration
        self._episode_memory: Optional["EpisodeMemory"] = None
        self._learning_engine: Optional["LearningEngine"] = None

    def register_agent(self, agent: BaseReproAgent) -> None:
        """Register an agent for coordination."""
        self.agents[agent.name] = agent

        # Pass LLMService to agent if available
        if self._llm_service and hasattr(agent, 'set_llm_service'):
            agent.set_llm_service(self._llm_service)

    def set_llm_service(self, service: "LLMService") -> None:
        """Set LLM service and propagate to all agents."""
        super().set_llm_service(service)

        # Propagate to all registered agents
        for agent in self.agents.values():
            if hasattr(agent, 'set_llm_service'):
                agent.set_llm_service(service)

    def set_memory(
        self,
        episode_memory: "EpisodeMemory" = None,
        learning_engine: "LearningEngine" = None,
    ) -> None:
        """Set memory systems for learning."""
        self._episode_memory = episode_memory
        self._learning_engine = learning_engine

    def _register_handlers(self) -> None:
        """Register message handlers."""
        self._message_handlers = {
            "task_complete": self._handle_task_complete,
            "task_failed": self._handle_task_failed,
            "status_update": self._handle_status_update,
        }

    def _handle_task_complete(self, msg: AgentMessage) -> Optional[AgentMessage]:
        """Handle task completion from an agent."""
        sender = msg.sender
        result = msg.payload.get("result")

        self.pipeline_state[f"{sender}_result"] = result
        self.pipeline_state[f"{sender}_status"] = "completed"

        return None

    def _handle_task_failed(self, msg: AgentMessage) -> Optional[AgentMessage]:
        """Handle task failure from an agent."""
        sender = msg.sender
        error = msg.payload.get("error")

        self.pipeline_state[f"{sender}_status"] = "failed"
        self.pipeline_state[f"{sender}_error"] = error

        # Log failure (full learning happens at pipeline end via _learn_from_result)
        logger.warning(f"Stage {sender} failed: {error}")

        return None

    def _handle_status_update(self, msg: AgentMessage) -> Optional[AgentMessage]:
        """Handle status update from an agent."""
        return None

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the full CVE reproduction pipeline.

        Args:
            context: Contains cve_info, config, etc.

        Returns:
            Pipeline results
        """
        self.set_state(AgentState.RUNNING)
        self.pipeline_state = {
            "cve_id": context.get("cve_id"),
            "start_time": context.get("start_time"),
            "attempts": {"analysis": 0, "generation": 0, "verification": 0},
        }

        cve_info = context.get("cve_info")
        settings = get_settings()

        try:
            # Stage 1: Analysis with retry
            analysis_result = self._run_stage_with_retry(
                stage="analysis",
                run_func=lambda: self._run_analysis(cve_info, context),
                context={"cve_info": cve_info},
            )

            if not analysis_result:
                return self._create_failure_result("Analysis failed after retries")

            # Update context for subsequent stages
            context["analysis"] = analysis_result

            # Stage 2: PoC Generation with retry
            poc_result = self._run_stage_with_retry(
                stage="generation",
                run_func=lambda: self._run_generation(analysis_result, cve_info, context),
                context={"cve_info": cve_info, "analysis": analysis_result},
            )

            if not poc_result:
                return self._create_failure_result("Generation failed after retries")

            # Stage 3: Verification with retry
            verify_result = self._run_stage_with_retry(
                stage="verification",
                run_func=lambda: self._run_verification(poc_result, analysis_result, context),
                context={
                    "cve_info": cve_info,
                    "analysis": analysis_result,
                    "poc": poc_result,
                },
            )

            if not verify_result:
                verify_result = {"success": False, "error": "Verification unavailable"}

            # Learn from result
            self._learn_from_result(
                cve_info=cve_info,
                analysis=analysis_result,
                poc=poc_result,
                verification=verify_result,
            )

            # Aggregate results
            self.set_state(AgentState.COMPLETED)
            return self._create_success_result(
                analysis_result, poc_result, verify_result
            )

        except Exception as e:
            logger.exception(f"Pipeline failed: {e}")
            self.set_state(AgentState.FAILED)
            return self._create_failure_result(str(e))

    def _run_stage_with_retry(
        self,
        stage: str,
        run_func,
        context: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Run a stage with retry logic based on critic feedback.

        Args:
            stage: Stage name (analysis, generation, verification)
            run_func: Function to run the stage
            context: Context for critic review

        Returns:
            Stage result or None if all retries failed
        """
        settings = get_settings()
        critic = self.agents.get("critic")

        for attempt in range(self.max_retries):
            self.pipeline_state["attempts"][stage] = attempt + 1
            print(f"  [Orchestrator] Running {stage} (attempt {attempt + 1}/{self.max_retries})...")
            logger.info(f"Running {stage} (attempt {attempt + 1}/{self.max_retries})")

            # Run the stage
            result = run_func()

            if not result:
                logger.warning(f"{stage} returned no result")
                continue

            # Get critic review if enabled
            if settings.agents.critic_enabled and critic:
                print(f"  [Orchestrator] Getting critic review for {stage}...")
                review = self._run_critic_review(stage, result, context)

                if review.get("approved"):
                    print(f"  [Orchestrator] {stage} APPROVED by critic")
                    logger.info(f"{stage} approved by critic")
                    return result

                # Not approved - check if we should retry
                if not critic.should_retry(stage):
                    print(f"  [Orchestrator] {stage} not approved but no retry suggestions")
                    logger.info(f"{stage} not approved but no retry suggestions")
                    return result

                # Get feedback for retry
                feedback = critic.get_retry_feedback(stage)
                print(f"  [Orchestrator] {stage} needs revision, retrying...")
                logger.info(f"{stage} needs revision: {feedback[:100]}...")

                # Store feedback for learning
                self.pipeline_state[f"{stage}_feedback"] = feedback

                # For generation stage, try to refine
                if stage == "generation" and attempt < self.max_retries - 1:
                    generator = self.agents.get("generator")
                    if generator and hasattr(generator, 'refine'):
                        logger.info("Attempting to refine PoC based on feedback")
                        refined = generator.refine(
                            poc=result,
                            feedback=feedback,
                            analysis=context.get("analysis", {}),
                        )
                        if refined and refined.get("code"):
                            result = refined
                            continue
            else:
                # No critic, return first result
                return result

        return result if result else None

    def _run_analysis(
        self,
        cve_info: CVEInfo,
        context: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Run the analysis stage."""
        print(f"  [Orchestrator] Starting analysis stage...")
        analyzer = self.agents.get("analyzer")
        if not analyzer:
            print(f"  [Orchestrator] ERROR: Analyzer agent not registered")
            logger.error("Analyzer agent not registered")
            return None

        request = AgentMessage.create_request(
            sender=self.name,
            receiver="analyzer",
            action="analyze",
            payload={
                "cve_info": cve_info.to_dict() if hasattr(cve_info, 'to_dict') else cve_info,
                "patches": context.get("patches", []),
            },
        )

        analyzer.receive(request)
        responses = analyzer.process_messages()

        for resp in responses:
            if resp.payload.get("success"):
                return resp.payload.get("result")
            else:
                logger.warning(f"Analysis failed: {resp.payload.get('error')}")

        return None

    def _run_generation(
        self,
        analysis: Dict[str, Any],
        cve_info: CVEInfo,
        context: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Run the PoC generation stage."""
        print(f"  [Orchestrator] Starting generation stage...")
        generator = self.agents.get("generator")
        if not generator:
            print(f"  [Orchestrator] ERROR: Generator agent not registered")
            logger.error("Generator agent not registered")
            return None

        request = AgentMessage.create_request(
            sender=self.name,
            receiver="generator",
            action="generate",
            payload={
                "analysis": analysis,
                "cve_info": cve_info.to_dict() if hasattr(cve_info, 'to_dict') else cve_info,
            },
        )

        generator.receive(request)
        responses = generator.process_messages()

        for resp in responses:
            if resp.payload.get("success"):
                return resp.payload.get("result")
            else:
                logger.warning(f"Generation failed: {resp.payload.get('error')}")

        return None

    def _run_verification(
        self,
        poc: Dict[str, Any],
        analysis: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Run the verification stage."""
        print(f"  [Orchestrator] Starting verification stage...")
        verifier = self.agents.get("verifier")
        if not verifier:
            print(f"  [Orchestrator] WARNING: Verifier agent not registered")
            logger.warning("Verifier agent not registered")
            return None

        request = AgentMessage.create_request(
            sender=self.name,
            receiver="verifier",
            action="verify",
            payload={
                "poc": poc,
                "analysis": analysis,
                "chrome_path": context.get("chrome_path"),
                "d8_path": context.get("d8_path"),
            },
        )

        verifier.receive(request)
        responses = verifier.process_messages()

        for resp in responses:
            return resp.payload.get("result")

        return None

    def _run_critic_review(
        self,
        stage: str,
        result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run critic review on a stage result."""
        critic = self.agents.get("critic")
        if not critic:
            return {"approved": True}

        request = AgentMessage.create_request(
            sender=self.name,
            receiver="critic",
            action="review",
            payload={
                "stage": stage,
                "result": result,
                "context": context,
            },
        )

        critic.receive(request)
        responses = critic.process_messages()

        for resp in responses:
            return resp.payload

        return {"approved": True}

    def _learn_from_result(
        self,
        cve_info: Any,
        analysis: Dict[str, Any],
        poc: Dict[str, Any],
        verification: Dict[str, Any],
    ) -> None:
        """Learn from pipeline result."""
        cve_id = cve_info.cve_id if hasattr(cve_info, 'cve_id') else cve_info.get("cve_id", "")
        success = verification.get("success", False)

        # Create case for learning
        from ...memory import CVECase

        case = CVECase(
            cve_id=cve_id,
            component=analysis.get("component", ""),
            vulnerability_type=analysis.get("vulnerability_type", ""),
            analysis_result=analysis,
            poc_result=poc,
            verify_result=verification,
            success=success,
        )

        if success:
            case.successful_strategy = analysis.get("poc_strategy", "")
            logger.info(f"Learning from successful case: {cve_id}")
        else:
            case.failed_approaches = [verification.get("error", "Unknown")]
            logger.info(f"Learning from failed case: {cve_id}")

        # Learn from case (handles both success and failure)
        if self._learning_engine:
            self._learning_engine.learn_from_case(case)

        # Also store in episode memory directly
        if self._episode_memory:
            self._episode_memory.save(case)

    def _create_success_result(
        self,
        analysis: Dict[str, Any],
        poc: Dict[str, Any],
        verification: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create success result."""
        return {
            "success": verification.get("success", False),
            "cve_id": self.pipeline_state.get("cve_id"),
            "analysis": analysis,
            "poc": poc,
            "verification": verification,
            "attempts": self.pipeline_state.get("attempts", {}),
        }

    def _create_failure_result(self, error: str) -> Dict[str, Any]:
        """Create failure result."""
        return {
            "success": False,
            "cve_id": self.pipeline_state.get("cve_id"),
            "error": error,
            "attempts": self.pipeline_state.get("attempts", {}),
        }
