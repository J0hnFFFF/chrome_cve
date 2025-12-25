"""
Learning Engine

Extracts lessons from CVE cases and updates knowledge.
"""

from typing import List, Dict, Any, Optional
from .episode import EpisodeMemory, CVECase
from .semantic import SemanticMemory


class LearningEngine:
    """
    Learns from CVE reproduction experiences.

    Features:
    - Extract insights from successful cases
    - Record lessons from failures
    - Update knowledge base with new patterns
    - Improve plugin templates
    """

    def __init__(
        self,
        episode_memory: EpisodeMemory,
        semantic_memory: SemanticMemory,
    ):
        self.episode_memory = episode_memory
        self.semantic_memory = semantic_memory

    def learn_from_case(self, case: CVECase) -> None:
        """
        Extract lessons from a completed case.

        For successful cases:
        - Record the successful strategy
        - Update component knowledge
        - Save effective plugins

        For failed cases:
        - Record what didn't work
        - Identify missing knowledge
        """
        if case.success:
            self._learn_from_success(case)
        else:
            self._learn_from_failure(case)

        # Save the case to episode memory
        self.episode_memory.save(case)

    def _learn_from_success(self, case: CVECase) -> None:
        """Extract lessons from a successful case."""
        # Record key insights
        if case.successful_strategy:
            insights = [
                f"Strategy for {case.component}/{case.vulnerability_type}: {case.successful_strategy}"
            ]
            case.key_insights.extend(insights)

        # TODO: Extract patterns for semantic memory
        # - Identify common trigger patterns
        # - Extract PoC templates
        # - Record exploitation steps

    def _learn_from_failure(self, case: CVECase) -> None:
        """Record lessons from a failed case."""
        # Document what was tried but failed
        if not case.failed_approaches:
            case.failed_approaches = ["Analysis completed but PoC generation failed"]

    def get_recommendations(
        self,
        component: str,
        vuln_type: str,
    ) -> List[str]:
        """
        Get recommendations based on past experiences.

        Args:
            component: Target component
            vuln_type: Vulnerability type

        Returns:
            List of recommendations
        """
        recommendations = []

        # Find similar successful cases
        similar = self.episode_memory.find_similar(
            component=component,
            vuln_type=vuln_type,
            success_only=True,
            limit=3,
        )

        for case in similar:
            if case.successful_strategy:
                recommendations.append(
                    f"Based on {case.cve_id}: {case.successful_strategy}"
                )
            for insight in case.key_insights[:2]:
                recommendations.append(insight)

        # Add known patterns from semantic memory
        knowledge = self.semantic_memory.get_knowledge_for_context(
            component=component,
            vuln_type=vuln_type,
        )
        if knowledge:
            recommendations.append(f"Known patterns available for {component}/{vuln_type}")

        return recommendations

    def get_failure_warnings(
        self,
        component: str,
        vuln_type: str,
    ) -> List[str]:
        """
        Get warnings about approaches that have failed before.

        Args:
            component: Target component
            vuln_type: Vulnerability type

        Returns:
            List of warnings
        """
        warnings = []

        # Find similar failed cases
        similar = self.episode_memory.find_similar(
            component=component,
            vuln_type=vuln_type,
            success_only=False,
            limit=5,
        )

        failed = [c for c in similar if not c.success]
        for case in failed:
            for approach in case.failed_approaches[:2]:
                warnings.append(f"Warning from {case.cve_id}: {approach} did not work")

        return warnings

    def get_context_for_analysis(
        self,
        component: str,
        vuln_type: str = None,
    ) -> str:
        """
        Get comprehensive context for vulnerability analysis.

        Combines:
        - Component knowledge
        - Past successful cases
        - Failure warnings
        """
        parts = []

        # Component knowledge
        ck = self.semantic_memory.get_component_knowledge(component)
        if ck:
            parts.append(f"# Component Knowledge: {ck.name}\n\n{ck.overview}")

        # Past successes
        recommendations = self.get_recommendations(component, vuln_type)
        if recommendations:
            parts.append(
                "# Recommendations from Past Cases\n\n" +
                "\n".join(f"- {r}" for r in recommendations)
            )

        # Warnings
        warnings = self.get_failure_warnings(component, vuln_type)
        if warnings:
            parts.append(
                "# Warnings (Approaches That Failed Before)\n\n" +
                "\n".join(f"- {w}" for w in warnings)
            )

        return "\n\n---\n\n".join(parts)
