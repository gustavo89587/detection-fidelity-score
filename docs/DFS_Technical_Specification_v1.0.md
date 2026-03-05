Detection Fidelity Score — Technical Specification v1.0
Gustavo Okamoto · Okamoto Security Labs · Detection Engineering / Signal Reliability Research

Abstract
Detection Fidelity Score (DFS) is a framework for evaluating detection systems as decision systems operating under operational cost and telemetry uncertainty. Security teams have historically measured detection coverage — whether rules exist for given adversary techniques — but have lacked a systematic way to measure the quality and trustworthiness of the signals those rules produce.
DFS addresses this gap by scoring detection signals across three orthogonal dimensions: Signal Strength, Telemetry Stability, and Behavioral Robustness. The resulting score determines the appropriate trust boundary for each detection, enabling rational decisions about when automation is safe, when analyst judgment is required, and when a detection is too fragile to act upon.

Core thesis: Security teams measure alerts. DFS measures detection signal quality. Detection should be evaluated as a decision system under operational cost.


1. Motivation and Problem Statement
1.1 The Alert Measurement Problem
Traditional detection engineering metrics focus on coverage: how many MITRE ATT&CK techniques have corresponding rules, how many rules are active, how many alerts fired. This approach systematically ignores signal quality, creating compounding operational problems:

Alert fatigue from high-noise detections drains analyst capacity
Automation built on low-fidelity signals propagates errors at machine speed
Deployed rules with unknown operational impact destabilize detection posture
Telemetry degradation silently breaks detections with no observable failure
Adversarial evolution renders rules unreliable without any signal to the team

The consequence is that SOC teams accumulate detection debt: a growing body of rules whose actual trustworthiness is unknown.
1.2 Detection as a Decision System
DFS reframes detection engineering around a more rigorous model. A detection is not merely a rule — it is a component in a decision pipeline that produces operational actions:
Telemetry Source
      │
      ▼
Collection / Normalization
      │
      ▼
Detection Logic
      │
      ▼
DFS Signal Evaluation      ← quality gate
      │
      ▼
Trust Boundary Decision
      │
      ▼
Human Analyst / AI Agent Action
Under this model, every detection produces a signal that must be evaluated for trustworthiness before it drives action. DFS is the evaluation layer between detection and decision.

2. Scoring Model
2.1 Core Formula
DFS = Signal_Strength × Telemetry_Stability × Behavioral_Robustness

where each dimension ∈ [0.0, 1.0]
and DFS ∈ [0.0, 1.0]
The multiplicative model reflects a key design decision: all three dimensions are necessary conditions for a trustworthy signal. A detection with perfect signal strength but unstable telemetry is not reliable. A detection with perfect stability but low behavioral robustness will fail under adversarial pressure.

Design rationale: An additive model (weighted sum) would allow a high score in one dimension to compensate for failure in another. The multiplicative model enforces that all three conditions must hold. If any dimension approaches zero, the overall score collapses — correctly reflecting that the signal cannot be trusted regardless of other properties.

2.2 Dimension Definitions
Signal Strength
Measures the inherent quality and specificity of the detection signal — how well the detection logic discriminates true positives from noise, independent of telemetry reliability.

High: low false positive rate, high behavioral specificity, narrow but precise scope
Low: broad behavioral patterns, high ambient noise, poor discrimination

Telemetry Stability
Measures the reliability and consistency of the underlying telemetry over time. A detection can have strong signal logic but be built on telemetry that is frequently absent, altered by pipeline changes, or subject to collection gaps.

High: telemetry is consistently present, schema is stable, collection is reliable
Low: missing fields, schema drift, collection outages, enrichment pipeline changes

Behavioral Robustness
Measures the resistance of the detection to adversarial evasion and behavioral drift. Detections that rely on static indicators degrade rapidly as adversaries evolve. Detections built on behavioral invariants — patterns that persist across evasion attempts — are more robust.

High: detection targets behavioral invariants, survives obfuscation and variation
Low: detection targets brittle indicators, fails under minor adversarial modification

2.3 Trust Tiers
ScoreTierActionOperational Implication> 0.70High TrustAUTOMATESignal is reliable. Automation and autonomous response are appropriate.0.40 – 0.70OperationalTRIAGESignal has value but requires analyst validation before action.< 0.40FragileHUMAN ONLYCannot drive automation. Flag for detection review.

3. Signal Degradation Model
DFS models three failure modes that cause detection signals to degrade in production environments.
3.1 Signal Loss
Signal loss occurs when telemetry fields required by the detection are absent. This can result from log source configuration changes, agent updates that alter event schema, collection pipeline failures, or environment changes.
Signal loss is the most operationally dangerous failure mode because it is silent — the detection continues to run but produces no alerts, creating a false sense of coverage.
3.2 Signal Distortion
Signal distortion occurs when telemetry fields are present but their semantic meaning has changed. The detection logic reads the field correctly, but the field no longer means what the detection assumes it means.
Distortion is harder to detect than loss because alerts may continue to fire — but with incorrect context, leading to false positives or missed true positives.
3.3 Signal Drift
Signal drift occurs when adversarial behavior evolves away from the patterns the detection targets. This is inevitable for any detection that targets specific indicators rather than behavioral invariants (hash rotation, filename variation, command-line obfuscation, LOLBin evolution).
DFS models this through the Behavioral Robustness dimension, which measures a detection's resistance to drift at evaluation time.

4. Operational Metrics
In addition to the detection-level DFS score, the framework computes system-level metrics that characterize the operational health of the detection environment as a whole.
MetricDefinitionFormulasignal_densityRate of meaningful signals relative to total alert volumehigh_trust_alerts / total_alertsinvestigation_pressureOperational load placed on analysts by triage-tier detectionstriage_alerts × avg_investigation_timeescalation_pressureRate at which triage investigations escalate to full incidentsescalations / triage_countautomation_coverageFraction of total detections eligible for automated responseauto_eligible / total_detectionsdecision_stabilityVariance of DFS scores across a detection pack over a rolling windowstddev(DFS_scores, window=30d)
These metrics answer questions like: Is this detection policy generating more noise? Is the system becoming more or less reliable over time? How much analyst capacity is this detection pack consuming?

5. DecisionCard Output Specification
Each evaluation produces a DecisionCard — a structured JSON object that captures the score, interpretation, recommended action, and the behavioral signals that informed the evaluation.
json{
  "kind": "windows-powershell-4104",
  "score": 0.6325,
  "interpretation": "Operational",
  "action": "TRIAGE",
  "action_reason": [
    "looks_amsi_bypass",
    "looks_download_cradle",
    "looks_reflection"
  ],
  "dimensions": {
    "signal_strength": 0.75,
    "telemetry_stability": 0.91,
    "behavioral_robustness": 0.92
  },
  "degradation_flags": [],
  "evaluated_at": "2025-03-05T14:22:00Z"
}
FieldDescriptionkindDetection type identifier. Used to select the appropriate scoring policy.scoreComposite DFS score. Product of the three dimension scores. Range: [0.0, 1.0].interpretationHuman-readable trust tier: High Trust, Operational, or Fragile.actionRecommended operational action: AUTOMATE, TRIAGE, or HUMAN ONLY.action_reasonBehavioral signals that most influenced the score.dimensionsIndividual scores for each dimension.degradation_flagsActive degradation conditions: loss, distortion, or drift events.evaluated_atISO 8601 timestamp of evaluation.

6. Scoring Policies
DFS scores are computed against policies — configuration files that define the thresholds, weights, and behavioral signals relevant to a specific detection type.
json{
  "kind": "windows-powershell-4104",
  "version": "0.2",
  "thresholds": {
    "high_trust":  0.70,
    "operational": 0.40
  },
  "weights": {
    "signal_strength":       0.40,
    "telemetry_stability":   0.30,
    "behavioral_robustness": 0.30
  },
  "behavioral_signals": {
    "looks_amsi_bypass":     { "weight": 0.85, "robustness_penalty": 0.10 },
    "looks_download_cradle": { "weight": 0.80, "robustness_penalty": 0.05 },
    "looks_reflection":      { "weight": 0.75, "robustness_penalty": 0.08 }
  },
  "telemetry_requirements": ["ScriptBlockText", "Path", "MessageNumber"]
}
Policy fields:

kind — Detection type this policy applies to
thresholds — Score boundaries that determine trust tier assignment
weights — Per-dimension contribution weights (must sum to 1.0)
behavioral_signals — Named patterns with scoring weight and robustness penalty
telemetry_requirements — Fields that must be present for full telemetry stability score


7. CLI Usage
Score a JSONL event file against a policy:
bashpython dfs_cli.py score ./examples/events_4104.jsonl \
  --kind windows-powershell-4104 \
  --policy ./policies/powershell_4104.policy.json \
  --limit 3
Run the full evaluation pipeline:
bashpython pipeline.py \
  --input ./datasets/cloudtrail_iam.jsonl \
  --kind cloudtrail-iam \
  --policy ./policies/cloudtrail_iam.policy.json \
  --output ./reports/

8. Integration with AI Agents
DFS provides a principled trust boundary for AI-driven SOC automation:
alert fires
      │
      ▼
DFS signal evaluation
      │
      ├── High Trust  →  agent may act autonomously
      ├── Operational →  agent may assist, human confirms
      └── Fragile     →  human only, agent must not act
This model prevents a critical failure mode: agents acting on low-fidelity signals at machine speed, compounding noise into operational disruption. DFS provides agents with a principled trust boundary, not just an alert.

9. Roadmap
Phase 1 — Detection CI/CD Infrastructure
DFS as a quality gate in the detection engineering workflow. Engineers get an impact report before any rule is deployed.
Phase 2 — Detection Observability Platform
Continuous monitoring of signal density, investigation pressure, escalation pressure, and decision stability. Enables detection posture dashboards and regression detection.
Phase 3 — Open Benchmark
DFS as an industry-standard benchmark for detection quality — analogous to ATT&CK Evaluations for EDR, applied to detection signal engineering.

10. Known Limitations

Ground truth gap: Score calibration is based on design intent and empirical tuning. Statistical validation against a labeled dataset of known-good and known-bad signals is in progress.
Multiplicative collapse sensitivity: The multiplicative model is sensitive to low values in any single dimension. Environments with systematically low telemetry stability may see scores that underrepresent detection quality.
Context invariance: The same detection may have different reliable fidelity in different environments. The current policy model does not capture environment-specific baselines.
Drift measurement latency: Behavioral Robustness is assessed at evaluation time based on static signal properties. Live drift detection via time-series is on the roadmap.
Limited telemetry adapters: Currently hardened for CloudTrail and Windows PowerShell 4104. Broader support (Sysmon, EDR, network) is planned.


License
Apache-2.0 — see LICENSE
