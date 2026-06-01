use std::path::Path;

use anyhow::{Context, Result};
use candle_core::quantized::gguf_file;
use candle_core::{DType, Device, Tensor};
use candle_transformers::generation::LogitsProcessor;
use candle_transformers::models::quantized_llama::ModelWeights;
use tokenizers::Tokenizer;

use crate::engine::osv::Vulnerability;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const MAX_NEW_TOKENS: usize = 256;
const TEMPERATURE: f64 = 0.1;
const SEED: u64 = 42;
// Context window kept short so inference stays fast on small models.
const MAX_CTX: usize = 512;

const SYSTEM_PROMPT: &str = "\
You are a security analyst. Summarise the CVE findings in ≤3 sentences. \
Always cite the CVE ID(s). \
Respond with ONLY a JSON object: {\"summary\": \"<text>\"}. \
No markdown, no extra keys.";

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(vulns: &[Vulnerability], model_path: &Path, tokenizer_path: &Path) -> Result<String> {
    let device = best_device();

    // Load GGUF weights.
    let mut file = std::fs::File::open(model_path)
        .with_context(|| format!("opening model file {}", model_path.display()))?;
    let content = gguf_file::Content::read(&mut file).context("parsing GGUF file")?;
    let mut model =
        ModelWeights::from_gguf(content, &mut file, &device).context("loading model weights")?;

    // Load tokenizer.
    let tokenizer = Tokenizer::from_file(tokenizer_path)
        .map_err(|e| anyhow::anyhow!("loading tokenizer: {}", e))?;

    // Build prompt and tokenise.
    let prompt = build_prompt(vulns);
    let encoding = tokenizer
        .encode(prompt.as_str(), true)
        .map_err(|e| anyhow::anyhow!("tokenising prompt: {}", e))?;
    let mut tokens: Vec<u32> = encoding.get_ids().to_vec();

    // EOS token ids — try common variants.
    let eos_id = tokenizer
        .token_to_id("</s>")
        .or_else(|| tokenizer.token_to_id("<|endoftext|>"))
        .or_else(|| tokenizer.token_to_id("<|im_end|>"))
        .unwrap_or(2);

    // Generation loop.
    let mut logits_proc = LogitsProcessor::new(SEED, Some(TEMPERATURE), None);
    let mut generated: Vec<u32> = Vec::with_capacity(MAX_NEW_TOKENS);

    for _ in 0..MAX_NEW_TOKENS {
        let ctx_start = tokens.len().saturating_sub(MAX_CTX);
        let input = Tensor::new(&tokens[ctx_start..], &device)?.unsqueeze(0)?;
        let logits = model
            .forward(&input, ctx_start)?
            .squeeze(0)?
            .squeeze(0)?
            .to_dtype(DType::F32)?;

        let next = logits_proc.sample(&logits)?;
        if next == eos_id {
            break;
        }
        tokens.push(next);
        generated.push(next);

        // Stop early if we have a closing brace — JSON is likely complete.
        if let Ok(partial) = tokenizer.decode(&generated, false) {
            if partial.contains('}') {
                break;
            }
        }
    }

    let raw = tokenizer
        .decode(&generated, true)
        .map_err(|e| anyhow::anyhow!("decoding output: {}", e))?;

    Ok(extract_summary(&raw).unwrap_or_else(|| raw.trim().to_string()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn best_device() -> Device {
    #[cfg(feature = "metal")]
    {
        Device::new_metal(0).unwrap_or(Device::Cpu)
    }
    #[cfg(all(feature = "cuda", not(feature = "metal")))]
    {
        Device::new_cuda(0).unwrap_or(Device::Cpu)
    }
    #[cfg(not(any(feature = "metal", feature = "cuda")))]
    {
        Device::Cpu
    }
}

pub(crate) fn build_prompt(vulns: &[Vulnerability]) -> String {
    let findings = vulns
        .iter()
        .map(|v| {
            format!(
                "- {} [{}]: {}",
                v.id,
                v.severity_label(),
                v.summary.as_deref().unwrap_or("no description available")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    // ChatML format, compatible with SmolLM2-Instruct and most Qwen models.
    format!(
        "<|im_start|>system\n{}<|im_end|>\n\
         <|im_start|>user\nVulnerabilities found:\n{}<|im_end|>\n\
         <|im_start|>assistant\n",
        SYSTEM_PROMPT, findings
    )
}

pub(crate) fn extract_summary(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end < start {
        return None;
    }
    let json_str = &text[start..=end];
    let value: serde_json::Value = serde_json::from_str(json_str).ok()?;
    value["summary"].as_str().map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(id: &str, severity: &str, summary: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_owned(),
            summary: Some(summary.to_owned()),
            cvss_vector: None,
            severity: Some(severity.to_owned()),
            fixed_version: None,
        }
    }

    #[test]
    fn build_prompt_includes_cve_id_and_severity() {
        let vulns = vec![vuln("GHSA-0001", "CRITICAL", "Remote code execution")];
        let prompt = build_prompt(&vulns);
        assert!(prompt.contains("GHSA-0001"));
        assert!(prompt.contains("CRITICAL"));
        assert!(prompt.contains("Remote code execution"));
    }

    #[test]
    fn build_prompt_includes_system_prompt() {
        let vulns = vec![vuln("GHSA-0001", "HIGH", "test")];
        let prompt = build_prompt(&vulns);
        assert!(prompt.contains("CVE ID"));
        assert!(prompt.contains("{\"summary\""));
    }

    #[test]
    fn extract_summary_parses_valid_json() {
        let text = r#"{"summary": "GHSA-0001 is a critical RCE vulnerability."}"#;
        assert_eq!(
            extract_summary(text),
            Some("GHSA-0001 is a critical RCE vulnerability.".into())
        );
    }

    #[test]
    fn extract_summary_handles_surrounding_text() {
        let text = r#"Here is the result: {"summary": "High severity issue in package."} Done."#;
        assert_eq!(
            extract_summary(text),
            Some("High severity issue in package.".into())
        );
    }

    #[test]
    fn extract_summary_returns_none_on_invalid_json() {
        assert!(extract_summary("not json at all").is_none());
        assert!(extract_summary("{}").is_none());
        assert!(extract_summary(r#"{"other": "value"}"#).is_none());
    }

    #[test]
    fn build_prompt_multiple_vulns() {
        let vulns = vec![
            vuln("GHSA-0001", "CRITICAL", "RCE in parser"),
            vuln("GHSA-0002", "HIGH", "SSRF in HTTP client"),
        ];
        let prompt = build_prompt(&vulns);
        assert!(prompt.contains("GHSA-0001"));
        assert!(prompt.contains("GHSA-0002"));
        assert!(prompt.contains("SSRF"));
    }
}
