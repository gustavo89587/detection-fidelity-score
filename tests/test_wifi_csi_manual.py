"""
Manual test for Wi-Fi CSI extractor.
Run: python test_wifi_csi_manual.py
"""
import sys
sys.path.insert(0, ".")
from dfs_core.features.wifi_csi import extract

CASES = {
    "Intruder: unknown gait, crawling (evasion)": {
        "sensor_id": "csi-node-01",
        "sensor_location": "server_room_entrance",
        "alert_id": "csi-alert-001",
        "timestamp": "2024-01-15T02:30:00Z",
        "alert_source": "esp32",
        "anomaly_type": "intruder_detected",
        "confidence": 0.92,
        "severity": "critical",
        "csi_matrix": {
            "subcarriers": 56, "amplitude_mean": 42.3,
            "phase_variance": 0.87, "rssi": -55.0,
            "snr": 28.0, "sample_rate_hz": 100.0, "packet_loss_pct": 1.2,
        },
        "biometric": {
            "motion_class": "crawling", "gait_score": 0.0,
            "breathing_bpm": 18.0, "mass_estimate_kg": 75.0, "person_count": 1,
            "is_human": True,
        },
        "rf_fingerprint": {"channel": "6", "is_known_device": False},
        "environment": {
            "calibration_age_seconds": 120, "noise_floor_db": -92.0,
            "multipath_count": 4, "is_calibrated": True, "jamming_score": 0.05,
        },
    },

    "Evil Twin / Rogue AP with ToF mismatch": {
        "sensor_id": "csi-node-02",
        "sensor_location": "office_floor_2",
        "alert_id": "csi-alert-002",
        "timestamp": "2024-01-15T10:15:00Z",
        "alert_source": "nexmon",
        "anomaly_type": "rogue_ap",
        "confidence": 0.88,
        "severity": "high",
        "csi_matrix": {
            "subcarriers": 52, "amplitude_mean": 38.1,
            "phase_variance": 0.45, "rssi": -62.0,
            "snr": 22.0, "sample_rate_hz": 50.0, "packet_loss_pct": 3.0,
        },
        "biometric": {"motion_class": "no_motion", "is_human": False, "person_count": 0},
        "rf_fingerprint": {
            "mac": "AA:BB:CC:DD:EE:FF",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "channel": "11",
            "tof_meters": 8.3,         # claims to be the router
            "expected_tof_meters": 2.1, # but router is here
            "fingerprint_id": "rf-unknown-001",
            "is_known_device": False,
        },
        "environment": {
            "calibration_age_seconds": 300, "noise_floor_db": -90.0,
            "multipath_count": 6, "is_calibrated": True, "jamming_score": 0.10,
        },
    },

    "RF Jamming attack detected": {
        "sensor_id": "csi-node-03",
        "sensor_location": "perimeter_lobby",
        "alert_id": "csi-alert-003",
        "timestamp": "2024-01-15T23:45:00Z",
        "alert_source": "cognitive_systems",
        "anomaly_type": "jamming_detected",
        "confidence": 0.85,
        "severity": "critical",
        "csi_matrix": {
            "subcarriers": 30, "amplitude_mean": 12.5,
            "phase_variance": 3.20, "rssi": -78.0,
            "snr": 4.0, "sample_rate_hz": 100.0, "packet_loss_pct": 45.0,
        },
        "biometric": {"motion_class": "unknown_gait", "is_human": True, "person_count": 2},
        "rf_fingerprint": {"channel": "6", "is_known_device": False},
        "environment": {
            "calibration_age_seconds": 600, "noise_floor_db": -60.0,
            "multipath_count": 12, "is_calibrated": True, "jamming_score": 0.91,
        },
    },

    "Person hiding (stationary, breathing detected)": {
        "sensor_id": "csi-node-04",
        "sensor_location": "warehouse_zone_b",
        "alert_id": "csi-alert-004",
        "timestamp": "2024-01-15T03:10:00Z",
        "alert_source": "intel5300",
        "anomaly_type": "breathing_detected",
        "confidence": 0.78,
        "csi_matrix": {
            "subcarriers": 30, "amplitude_mean": 15.2,
            "phase_variance": 0.22, "rssi": -68.0,
            "snr": 18.0, "sample_rate_hz": 50.0, "packet_loss_pct": 5.0,
        },
        "biometric": {
            "motion_class": "stationary_human", "gait_score": 0.0,
            "breathing_bpm": 14.0, "mass_estimate_kg": 80.0,
            "person_count": 1, "is_human": True,
        },
        "rf_fingerprint": {"channel": "1", "is_known_device": False},
        "environment": {
            "calibration_age_seconds": 900, "noise_floor_db": -91.0,
            "multipath_count": 3, "is_calibrated": True, "jamming_score": 0.02,
        },
    },

    "Authorized user — known gait, calibrated": {
        "sensor_id": "csi-node-01",
        "sensor_location": "server_room_entrance",
        "alert_id": "csi-alert-005",
        "timestamp": "2024-01-15T09:00:00Z",
        "alert_source": "esp32",
        "anomaly_type": "human_presence",
        "confidence": 0.95,
        "csi_matrix": {
            "subcarriers": 56, "amplitude_mean": 40.0,
            "phase_variance": 0.31, "rssi": -52.0,
            "snr": 30.0, "sample_rate_hz": 100.0, "packet_loss_pct": 0.5,
        },
        "biometric": {
            "motion_class": "authorized_user", "gait_score": 0.97,
            "breathing_bpm": 16.0, "mass_estimate_kg": 72.0,
            "person_count": 1, "is_human": True,
        },
        "rf_fingerprint": {
            "mac": "11:22:33:44:55:66", "channel": "6",
            "tof_meters": 2.1, "expected_tof_meters": 2.0,
            "is_known_device": True,
        },
        "environment": {
            "calibration_age_seconds": 60, "noise_floor_db": -93.0,
            "multipath_count": 3, "is_calibrated": True, "jamming_score": 0.01,
        },
    },

    "Stale calibration + high packet loss (degraded)": {
        "sensor_id": "csi-node-05",
        "sensor_location": "parking_entrance",
        "alert_id": "csi-alert-006",
        "timestamp": "2024-01-15T04:00:00Z",
        "alert_source": "esp32",
        "anomaly_type": "human_presence",
        "confidence": 0.55,
        "csi_matrix": {
            "subcarriers": 20, "amplitude_mean": 8.0,
            "phase_variance": 1.80, "rssi": -85.0,
            "snr": 6.0, "sample_rate_hz": 20.0, "packet_loss_pct": 38.0,
        },
        "biometric": {"motion_class": "unknown_gait", "is_human": True, "person_count": 1},
        "rf_fingerprint": {"channel": "11", "is_known_device": False},
        "environment": {
            "calibration_age_seconds": 14400, "noise_floor_db": -75.0,
            "multipath_count": 9, "is_calibrated": False, "jamming_score": 0.15,
        },
    },
}

print(f"\n{'='*76}")
print(f"{'CASE':<46} {'S':>6} {'T':>6} {'B':>6} {'DFS':>7}")
print(f"{'='*76}")

for name, event in CASES.items():
    inputs, flags = extract(event)
    dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)
    print(f"{name:<46} {inputs.signal:>6.3f} {inputs.trust:>6.3f} {inputs.overlap:>6.3f} {dfs:>7.4f}")
    risk_flags = [k for k, v in flags.items() if v is True and (
        k.startswith("is_") or k.startswith("tof_") or
        k in ("high_packet_loss", "stale_calibration", "multiple_persons", "high_confidence")
    )]
    if risk_flags:
        print(f"  flags: {', '.join(risk_flags[:6])}")

print(f"{'='*76}\n")
