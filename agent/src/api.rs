use crate::config::normalize_server_url;
use crate::models::{
    ApiErrorEnvelope, CheckinRequest, CheckinResponse, ComplianceReportRequest,
    ComplianceReportResponse, EnrollRequest, EnrollResponse,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;

pub struct AgentApiClient {
    server_url: String,
    agent: ureq::Agent,
}

impl AgentApiClient {
    pub fn new(server_url: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(30))
            .timeout_write(Duration::from_secs(30))
            .user_agent(&format!("ns8-policy-agent/{}", env!("CARGO_PKG_VERSION")))
            .build();

        Self {
            server_url: normalize_server_url(server_url),
            agent,
        }
    }

    pub fn enroll(
        &self,
        payload: &EnrollRequest,
        idempotency_key: Option<&str>,
    ) -> Result<EnrollResponse, String> {
        let url = format!("{}/api/v1/agent/enroll", self.server_url);
        let mut req = self.agent.post(&url).set("Accept", "application/json");
        if let Some(key) = idempotency_key {
            if !key.trim().is_empty() {
                req = req.set("Idempotency-Key", key);
            }
        }
        Self::send_json(req, payload)
    }

    pub fn checkin(
        &self,
        device_token: &str,
        payload: &CheckinRequest,
    ) -> Result<CheckinResponse, String> {
        let url = format!("{}/api/v1/agent/checkin", self.server_url);
        let req = self
            .agent
            .post(&url)
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {}", device_token));
        Self::send_json(req, payload)
    }

    pub fn report_compliance(
        &self,
        device_token: &str,
        payload: &ComplianceReportRequest,
    ) -> Result<ComplianceReportResponse, String> {
        let url = format!("{}/api/v1/agent/compliance", self.server_url);
        let req = self
            .agent
            .post(&url)
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {}", device_token));
        Self::send_json(req, payload)
    }

    fn send_json<Req: Serialize, Resp: DeserializeOwned>(
        req: ureq::Request,
        payload: &Req,
    ) -> Result<Resp, String> {
        let value = serde_json::to_value(payload)
            .map_err(|e| format!("Failed to serialize request JSON: {}", e))?;

        match req.send_json(value) {
            Ok(resp) => {
                let body = resp
                    .into_string()
                    .map_err(|e| format!("Failed to read HTTP response body: {}", e))?;
                serde_json::from_str::<Resp>(&body).map_err(|e| {
                    format!(
                        "Failed to deserialize server JSON response ({}): {}",
                        e, body
                    )
                })
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                if let Ok(err_env) = serde_json::from_str::<ApiErrorEnvelope>(&body) {
                    Err(format!(
                        "HTTP {} [{}]: {}",
                        code, err_env.error.code, err_env.error.message
                    ))
                } else {
                    Err(format!("HTTP {} error: {}", code, body.trim()))
                }
            }
            Err(ureq::Error::Transport(transport)) => {
                Err(format!("Network transport error: {}", transport))
            }
        }
    }
}
