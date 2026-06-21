#pragma once
#include "MLClient.h"
#include "../response/FirewallController.h"
#include "../response/AlertManager.h"
#include "../common/Types.h"

#include <memory>

class ThreatDetector {
public:
    ThreatDetector(std::shared_ptr<FirewallController> firewall,
                   std::shared_ptr<AlertManager>       alert)
        : firewall_(firewall), alert_(alert) {}

    DetectionResult analyze(const Features& features) {
        DetectionResult result = ml_client_.predict(features);

        if (result.status == "THREAT") {
            if (firewall_ && !features.src_ip.empty())
                firewall_->block_ip(features.src_ip);
            if (alert_)
                alert_->send_alert("THREAT DETECTED: " + result.attack_type
                                   + " from " + features.src_ip);
        }
        return result;
    }

private:
    MLClient                            ml_client_;
    std::shared_ptr<FirewallController> firewall_;
    std::shared_ptr<AlertManager>       alert_;
};
