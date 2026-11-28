use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocVerdict {
    pub action: String,
    pub ip: String,
    pub reason: String,
    pub source: String,
}

pub async fn triage(llm_base: &str, recent_events: &[String], suspect_ip: &str) -> SocVerdict {
    let prompt = format!(
        "You are an air-gapped autonomous SOC analyst. Inspect these kernel/cortex events and reply ONLY with JSON {{\"action\":\"block_ip\"|\"monitor\",\"ip\":\"{}\",\"reason\":\"short\"}}.\nEvents:\n{}",
        suspect_ip,
        recent_events.join("\n")
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let body = serde_json::json!({
        "model": "local",
        "temperature": 0.1,
        "max_tokens": 128,
        "messages": [
            { "role": "system", "content": "Output strict JSON only." },
            { "role": "user", "content": prompt }
        ]
    });

    if let Ok(resp) = client
        .post(format!("{}/v1/chat/completions", llm_base.trim_end_matches('/')))
        .json(&body)
        .send()
        .await
    {
        if let Ok(val) = resp.json::<serde_json::Value>().await {
            if let Some(txt) = val["choices"][0]["message"]["content"].as_str() {
                if let (Some(s), Some(e)) = (txt.find('{'), txt.rfind('}')) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt[s..=e]) {
                        return SocVerdict {
                            action: v["action"].as_str().unwrap_or("monitor").to_string(),
                            ip: v["ip"].as_str().unwrap_or(suspect_ip).to_string(),
                            reason: v["reason"].as_str().unwrap_or("LLM triage").to_string(),
                            source: "llama.cpp".into(),
                        };
                    }
                }
            }
        }
    }

    let high_risk = recent_events.iter().filter(|e| e.contains("SYN") || e.contains("SPIKE")).count() >= 5;
    SocVerdict {
        action: if high_risk && !suspect_ip.starts_with("127.") { "block_ip".into() } else { "monitor".into() },
        ip: suspect_ip.into(),
        reason: if high_risk {
            "Autonomous fallback: burst SYN/surprise threshold exceeded".into()
        } else {
            "llama-server offline; baseline within tolerance".into()
        },
        source: "deterministic_guard".into(),
    }
}
