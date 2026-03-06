# dfs_core/features/wifi_csi.py
"""
Wi-Fi CSI (Channel State Information) Event → DFS Inputs

CSI captures how Wi-Fi signals propagate through the environment.
Every movement, breath, heartbeat, and physical presence changes
the multipath propagation — CSI captures this as a matrix of
complex numbers (amplitude + phase) per subcarrier.

Sources supported:
  - ESP32 CSI Toolkit (open source)
  - Intel 5300 NIC (Linux CSI Tool)
  - Nexmon CSI (Raspberry Pi / BCM chips)
  - Commercial: Cognitive Systems Aura, Aerial
  - Custom SDR-based collectors

DFS Mapping:
  S (Signal Clarity):   Anomaly type + biometric confidence + RF threat signals
  T (Telemetry):        CSI matrix completeness + sensor health + calibration state
  B (Behavioral):       Coherence between physical signal and claimed device identity

Key threat patterns:
  - Human presence detection (intruder)
  - Gait analysis mismatch (unknown person)
  - Breathing pattern anomaly (person hiding/still)
  - Evil Twin / Rogue AP (ToF position mismatch)
  - RF jamming attempt (artificial noise spike)
  - Physical device spoofing (MAC claims != RF fingerprint)
  - Shadow device detection (new RF source not in inventory)

Event schema (unified across collectors):
  sensor_id, sensor_location, timestamp
  anomaly_type: human_presence | gait_anomaly | breathing | rogue_ap |
                jamming | spoofing | shadow_device | environment_change
  confidence: 0.0-1.0 (ML model confidence)
  csi_matrix: {subcarriers, amplitude_mean, phase_variance, rssi}
  biometric: {motion_class, gait_score, breathing_bpm, mass_estimate}
  rf_fingerprint: {mac, bssid, channel, tof_meters, expected_tof_meters}
  environment: {calibration_age_seconds, noise_floor_db, multipath_count}
  alert_source: esp32 | intel5300 | nexmon | cognitive_systems | custom
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
from dfs_core.scoring import DFSInputs


def _get(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown", "n/a"):
        return False
    return True


def _clean(v: Any) -> Optional[str]:
    return str(v) if _truthy(v) else None


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(v)))


# ---------------------------------------------------------------------------
# Anomaly type risk classification
# ---------------------------------------------------------------------------

_ANOMALY_RISK = {
    # Physical intrusion
    "human_presence":       0.85,  # person detected in monitored space
    "intruder_detected":    0.92,  # confirmed human, not in authorized list
    "gait_anomaly":         0.78,  # unknown gait signature
    "breathing_detected":   0.70,  # person hiding / stationary
    "multiple_humans":      0.88,  # more people than expected

    # RF threats
    "rogue_ap":             0.90,  # evil twin / rogue access point
    "jamming_detected":     0.88,  # artificial RF noise injection
    "spoofing_detected":    0.92,  # MAC/identity spoofing + ToF mismatch
    "shadow_device":        0.80,  # unregistered RF source detected
    "deauth_flood":         0.85,  # deauthentication attack

    # Environmental / calibration
    "environment_change":   0.35,  # furniture moved, layout changed
    "calibration_drift":    0.25,  # sensor needs recalibration
    "noise_spike":          0.45,  # temporary RF noise (non-malicious)
    "multipath_anomaly":    0.40,  # unusual signal reflections
}

# Biometric motion classes
_MOTION_CLASS_RISK = {
    "authorized_user":      0.05,
    "known_gait":           0.10,
    "unknown_gait":         0.75,
    "stationary_human":     0.65,
    "crawling":             0.88,  # evasion behavior
    "running":              0.70,
    "multiple_persons":     0.82,
    "animal":               0.10,
    "object_movement":      0.05,
    "no_motion":            0.02,
}


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps Wi-Fi CSI anomaly event → (DFSInputs, flags).

    Accepts events from ESP32, Intel 5300, Nexmon, or any
    collector that follows the unified DFS CSI schema.
    """

    # ── Sensor identity ──────────────────────────────────────────────────────
    sensor_id       = _clean(event.get("sensor_id"))
    sensor_location = _clean(event.get("sensor_location") or event.get("location"))
    alert_source    = _clean(event.get("alert_source") or event.get("source") or "unknown")
    timestamp       = _clean(event.get("timestamp") or event.get("time"))
    sensor_version  = _clean(event.get("sensor_version"))

    # ── Anomaly classification ───────────────────────────────────────────────
    anomaly_type    = _clean(event.get("anomaly_type") or event.get("alert_type") or "unknown")
    confidence      = float(event.get("confidence") or event.get("ml_confidence") or 0.0)
    severity        = _clean(event.get("severity") or "medium")
    alert_id        = _clean(event.get("alert_id") or event.get("id"))

    # ── CSI matrix quality ───────────────────────────────────────────────────
    csi             = event.get("csi_matrix") or event.get("csi") or {}
    subcarriers     = int(csi.get("subcarriers") or csi.get("subcarrier_count") or 0)
    amplitude_mean  = float(csi.get("amplitude_mean") or csi.get("mean_amplitude") or 0.0)
    phase_variance  = float(csi.get("phase_variance") or csi.get("variance") or 0.0)
    rssi            = float(csi.get("rssi") or csi.get("signal_strength") or -100.0)
    snr             = float(csi.get("snr") or csi.get("signal_noise_ratio") or 0.0)
    sample_rate_hz  = float(csi.get("sample_rate_hz") or csi.get("sample_rate") or 0.0)
    packet_loss_pct = float(csi.get("packet_loss_pct") or csi.get("loss") or 0.0)

    # ── Biometric signals ────────────────────────────────────────────────────
    bio             = event.get("biometric") or event.get("bio") or {}
    motion_class    = _clean(bio.get("motion_class") or bio.get("class"))
    gait_score      = float(bio.get("gait_score") or bio.get("gait_confidence") or 0.0)
    breathing_bpm   = float(bio.get("breathing_bpm") or bio.get("respiration_rate") or 0.0)
    mass_estimate   = float(bio.get("mass_estimate_kg") or bio.get("mass_kg") or 0.0)
    person_count    = int(bio.get("person_count") or bio.get("human_count") or 0)
    is_human        = bool(bio.get("is_human") or person_count > 0)

    # ── RF fingerprint / device identity ────────────────────────────────────
    rf              = event.get("rf_fingerprint") or event.get("rf") or {}
    mac_address     = _clean(rf.get("mac") or rf.get("mac_address"))
    bssid           = _clean(rf.get("bssid"))
    channel         = _clean(rf.get("channel"))
    tof_measured    = float(rf.get("tof_meters") or rf.get("tof_distance_m") or -1.0)
    tof_expected    = float(rf.get("expected_tof_meters") or rf.get("known_position_m") or -1.0)
    rf_fingerprint  = _clean(rf.get("fingerprint_id") or rf.get("rf_id"))
    known_device    = bool(rf.get("is_known_device") or rf.get("in_inventory"))

    # ── Environment / calibration ────────────────────────────────────────────
    env             = event.get("environment") or event.get("env") or {}
    calibration_age = float(env.get("calibration_age_seconds") or env.get("cal_age_s") or 0.0)
    noise_floor_db  = float(env.get("noise_floor_db") or env.get("noise_floor") or -95.0)
    multipath_count = int(env.get("multipath_count") or env.get("reflections") or 0)
    is_calibrated   = bool(env.get("is_calibrated") or calibration_age < 3600)
    jamming_score   = float(env.get("jamming_score") or env.get("interference_score") or 0.0)

    # ── Derived signals ──────────────────────────────────────────────────────
    anomaly_lower   = (anomaly_type or "").lower()
    anomaly_risk    = _ANOMALY_RISK.get(anomaly_lower, 0.40)
    motion_risk     = _MOTION_CLASS_RISK.get((motion_class or "").lower(), 0.30)

    # ToF position mismatch — physical impostor detection
    tof_mismatch    = (
        tof_measured >= 0 and tof_expected >= 0 and
        abs(tof_measured - tof_expected) > 1.5  # >1.5 meters = suspicious
    )
    tof_delta       = abs(tof_measured - tof_expected) if tof_measured >= 0 and tof_expected >= 0 else 0.0

    # Signal quality indicators
    good_rssi       = rssi >= -70.0   # strong enough for reliable CSI
    good_snr        = snr >= 15.0     # clean signal
    good_subcarriers = subcarriers >= 30  # sufficient frequency resolution
    high_packet_loss = packet_loss_pct > 20.0  # degraded telemetry
    stale_calibration = calibration_age > 7200  # >2 hours = drift risk

    # RF threat indicators
    is_jamming      = jamming_score >= 0.65 or "jamming" in anomaly_lower
    is_rogue_ap     = "rogue" in anomaly_lower or "evil_twin" in anomaly_lower
    is_spoofing     = "spoof" in anomaly_lower or tof_mismatch
    is_shadow_dev   = "shadow" in anomaly_lower or (not known_device and _truthy(mac_address))
    is_deauth       = "deauth" in anomaly_lower

    # Physical threat indicators
    is_intruder     = is_human and ("intruder" in anomaly_lower or "unknown" in (motion_class or "").lower())
    is_hiding       = "breathing" in anomaly_lower or (is_human and motion_class == "stationary_human")
    is_evasion      = motion_class == "crawling"
    high_confidence = confidence >= 0.75
    low_confidence  = confidence < 0.40

    # Presence flags
    has_sensor_id   = sensor_id is not None
    has_location    = sensor_location is not None
    has_timestamp   = timestamp is not None
    has_anomaly     = _truthy(anomaly_type) and anomaly_type != "unknown"
    has_confidence  = confidence > 0.0
    has_csi_data    = subcarriers > 0 or amplitude_mean > 0
    has_biometric   = _truthy(motion_class) or breathing_bpm > 0
    has_rf_data     = _truthy(mac_address) or _truthy(bssid)
    has_tof         = tof_measured >= 0
    has_calibration = _truthy(calibration_age) or is_calibrated
    has_alert_id    = alert_id is not None

    # ── T — Telemetry Completeness ───────────────────────────────────────────
    sensor_fields   = [has_sensor_id, has_location, has_timestamp, has_alert_id]
    signal_fields   = [has_csi_data, good_rssi, good_subcarriers, not high_packet_loss]
    context_fields  = [has_biometric, has_rf_data, has_tof, has_calibration]
    quality_fields  = [is_calibrated, not stale_calibration, good_snr]

    t = (
        sum(1.0 for x in sensor_fields if x) / max(len(sensor_fields), 1) * 0.30 +
        sum(1.0 for x in signal_fields if x) / max(len(signal_fields), 1) * 0.35 +
        sum(1.0 for x in context_fields if x) / max(len(context_fields), 1) * 0.20 +
        sum(1.0 for x in quality_fields if x) / max(len(quality_fields), 1) * 0.15
    )

    # Penalize heavily degraded telemetry
    if high_packet_loss:    t = _clamp(t - 0.15)
    if stale_calibration:   t = _clamp(t - 0.10)
    if not is_calibrated:   t = _clamp(t - 0.10)

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    # Blend anomaly type risk + ML confidence + biometric evidence
    s = (anomaly_risk * 0.45) + (confidence * 0.30) + (motion_risk * 0.25)

    # RF threat boosts
    if tof_mismatch:            s = _clamp(s + 0.12 + min(tof_delta * 0.03, 0.10))
    if is_jamming:              s = _clamp(s + 0.10)
    if is_rogue_ap:             s = _clamp(s + 0.08)
    if is_spoofing:             s = _clamp(s + 0.10)
    if is_shadow_dev:           s = _clamp(s + 0.07)

    # Physical threat boosts
    if is_evasion:              s = _clamp(s + 0.10)  # crawling = deliberate evasion
    if is_hiding:               s = _clamp(s + 0.08)
    if person_count > 1:        s = _clamp(s + 0.05)  # multiple intruders

    # Confidence calibration
    if low_confidence:          s = _clamp(s - 0.15)  # ML not sure
    if not is_calibrated:       s = _clamp(s - 0.10)  # can't trust signal

    s = _clamp(s)

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    # Coherence = physical signal matches claimed device identity + environment makes sense
    b = 0.35

    if has_sensor_id:           b += 0.10
    if has_location:            b += 0.08
    if has_biometric:           b += 0.10
    if is_calibrated:           b += 0.10
    if has_tof:                 b += 0.08
    if has_rf_data:             b += 0.07
    if has_csi_data:            b += 0.07
    if high_confidence:         b += 0.05

    # Incoherence penalties
    if tof_mismatch:            b = _clamp(b - 0.15)  # position doesn't match claimed identity
    if stale_calibration:       b = _clamp(b - 0.10)  # environment model is outdated
    if high_packet_loss:        b = _clamp(b - 0.08)  # broken data stream
    if is_jamming:              b = _clamp(b - 0.05)  # adversarial interference

    b = _clamp(b)

    flags = {
        # Standard DFS
        "has_user":                 is_human,
        "has_host":                 has_sensor_id,
        "has_command_line":         has_biometric,
        "has_process_path":         has_anomaly,
        "has_parent_process":       has_location,
        # CSI-specific
        "has_sensor_id":            has_sensor_id,
        "has_location":             has_location,
        "has_csi_data":             has_csi_data,
        "has_biometric":            has_biometric,
        "has_rf_data":              has_rf_data,
        "has_tof":                  has_tof,
        "is_calibrated":            is_calibrated,
        "good_signal_quality":      good_rssi and good_snr,
        # Physical threats
        "is_human":                 is_human,
        "is_intruder":              is_intruder,
        "is_hiding":                is_hiding,
        "is_evasion":               is_evasion,
        "multiple_persons":         person_count > 1,
        # RF threats
        "is_jamming":               is_jamming,
        "is_rogue_ap":              is_rogue_ap,
        "is_spoofing":              is_spoofing,
        "is_shadow_device":         is_shadow_dev,
        "is_deauth_attack":         is_deauth,
        "tof_position_mismatch":    tof_mismatch,
        "unknown_device":           not known_device and has_rf_data,
        # Telemetry health
        "high_packet_loss":         high_packet_loss,
        "stale_calibration":        stale_calibration,
        "high_confidence":          high_confidence,
        "low_confidence":           low_confidence,
    }

    return DFSInputs(_clamp(s), _clamp(t), _clamp(b)), flags


def wifi_csi_to_inputs_and_flags(event):
    return extract(event)
