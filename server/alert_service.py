from database import Alert

class AlertService:
    def evaluate(self, log_id, anomaly_score, parsed_json):
        """
        Evaluates the anomaly score against thresholds to return an Alert object (or None).
        0.0 - 0.4 -> Normal
        0.41 - 0.6 -> LOW
        0.61 - 0.8 -> MEDIUM
        0.81 - 0.9 -> HIGH
        > 0.9 -> CRITICAL
        """
        severity = None
        recommended_action = "None required"
        reason = "Normal operation"

        if anomaly_score > 0.9:
            severity = "CRITICAL"
            reason = "Extreme deviation from normal sequences or features (e.g., suspicious admin access or data exfiltration pattern)"
            recommended_action = "Instantly isolate IP and notify SOC."
        elif anomaly_score > 0.8:
            severity = "HIGH"
            reason = "Multiple failed login attempts or high error frequency detected"
            recommended_action = "Block IP temporarily and require 2FA."
        elif anomaly_score > 0.6:
            severity = "MEDIUM"
            reason = "Unusual rate of events or new template sequence"
            recommended_action = "Monitor closely for escalation."
        elif anomaly_score > 0.4:
            severity = "LOW"
            reason = "Minor deviations in timing and burst thresholds"
            recommended_action = "Log for audit."

        if severity:
            alert = Alert(
                log_id=log_id,
                anomaly_score=anomaly_score,
                severity=severity,
                reason=reason,
                recommended_action=recommended_action
            )
            return alert
            
        return None
