//! # mcpg-plugin-payment-x402
//!
//! x402 (Coinbase) crypto micropayment plugin for the MCPG gateway.
//!
//! Implements the x402 payment protocol which uses EIP-712 typed data signatures
//! for simple per-tool-call crypto micropayments. A facilitator service verifies
//! on-chain transactions.
//!
//! ## How it works
//!
//! 1. Per-binding charge configs map tool names to payment requirements
//! 2. On pre-dispatch, if no credential in `_meta["x402/payment"]` → issue 402 challenge
//! 3. If credential present → call facilitator `/verify` endpoint → receipt or deny
//! 4. On post-dispatch, attach receipt in `_meta["x402/receipt"]`

use std::collections::BTreeMap;

use anyhow::Result;
use mcpg_plugin_protocol::{
    GateDecision, PluginClass, PluginContext, PluginManifest, ToolGatePlugin, async_trait,
    payment::{PaymentAwarePlugin, PaymentCapability, PaymentCategory, PaymentProtocol},
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

const PLUGIN_ID: &str = "dev.mcpg.payment.x402";

// ---------------------------------------------------------------------------
// Config types (operator-facing)
// ---------------------------------------------------------------------------

/// Top-level x402 protocol configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402ProtocolConfig {
    /// RPC URLs per chain.
    /// Key: chain identifier (e.g. "eip155:8453" for Base).
    /// Value: RPC endpoint URL.
    #[serde(default)]
    pub rpc_urls: BTreeMap<String, String>,

    /// Facilitator service URL for payment verification.
    /// Example: "https://x402.org/facilitator"
    pub facilitator_url: String,

    /// Default recipient address for payments.
    pub recipient_address: String,

    /// HTTP timeout for facilitator calls (seconds).
    #[serde(default = "default_http_timeout")]
    pub http_timeout_ms: u64,
}

fn default_http_timeout() -> u64 {
    10
}

/// Per-tool x402 payment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402ToolConfig {
    /// Charge amount per call (e.g., "0.001").
    pub charge: String,

    /// Token/currency (e.g., "USDC", "ETH").
    #[serde(default = "default_currency")]
    pub currency: String,

    /// Chain identifier (e.g., "eip155:8453" for Base mainnet).
    #[serde(default = "default_chain")]
    pub chain_id: String,

    /// Override the global recipient for this tool.
    #[serde(default)]
    pub recipient: Option<String>,
}

fn default_currency() -> String {
    "USDC".into()
}

fn default_chain() -> String {
    "eip155:8453".into()
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/// x402 payment plugin.
///
/// Implements simple per-tool-call crypto micropayments using the x402 protocol.
/// The gateway acts as the resource server; a facilitator verifies payments.
pub struct X402PaymentPlugin {
    manifest: PluginManifest,
    enabled: bool,
    tool_configs: BTreeMap<String, X402ToolConfig>,
    facilitator_url: String,
    default_recipient: String,
    http_client: reqwest::blocking::Client,
}

impl std::fmt::Debug for X402PaymentPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402PaymentPlugin")
            .field("enabled", &self.enabled)
            .field("tool_configs", &self.tool_configs)
            .finish()
    }
}

// Payment codes live outside the MCP-reserved JSON-RPC range
// (-32000..-32099) to avoid collision with future spec assignments.

/// JSON-RPC error code for x402 payment required.
const X402_PAYMENT_REQUIRED_CODE: i32 = -33060;
/// JSON-RPC error code for x402 payment verification failure.
const X402_VERIFICATION_FAILED_CODE: i32 = -33061;

impl X402PaymentPlugin {
    /// Create a disabled (no-op) plugin.
    pub fn disabled() -> Self {
        Self {
            manifest: Self::make_manifest(),
            enabled: false,
            tool_configs: BTreeMap::new(),
            facilitator_url: String::new(),
            default_recipient: String::new(),
            http_client: reqwest::blocking::Client::new(),
        }
    }

    /// Create from protocol config and binding configs.
    pub fn from_config(
        config: &X402ProtocolConfig,
        tool_configs: BTreeMap<String, X402ToolConfig>,
    ) -> Result<Self> {
        if tool_configs.is_empty() {
            return Ok(Self::disabled());
        }

        if config.facilitator_url.is_empty() {
            return Err(anyhow::anyhow!(
                "x402: facilitator_url is required when x402 tools are configured"
            ));
        }
        if config.recipient_address.is_empty() {
            return Err(anyhow::anyhow!("x402: recipient_address is required"));
        }

        // Validate each tool's charge is a positive number
        for (tool_name, tool_cfg) in &tool_configs {
            match tool_cfg.charge.parse::<f64>() {
                Ok(v) if v > 0.0 && v.is_finite() => {}
                _ => {
                    return Err(anyhow::anyhow!(
                        "x402: invalid charge '{}' for tool '{}'",
                        tool_cfg.charge,
                        tool_name,
                    ));
                }
            }
        }

        let http_client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(config.http_timeout_ms))
            .build()
            .unwrap_or_default();

        Ok(Self {
            manifest: Self::make_manifest(),
            enabled: true,
            tool_configs,
            facilitator_url: config.facilitator_url.clone(),
            default_recipient: config.recipient_address.clone(),
            http_client,
        })
    }

    fn make_manifest() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            name: "x402 Crypto Micropayments".into(),
            plugin_class: PluginClass::ToolGate,
            protocol_version: "1.0".into(),
            // Verify + settle calls go to the facilitator URL.
            license: None,
            required_capabilities: Vec::new(), // host-derived from declare_plugin! capabilities (typed)
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!()
                .split("::")
                .next()
                .unwrap_or("")
                .to_owned(),
            backend_profile: None,
        }
    }

    /// SDK macro factory: parses operator config JSON. The cdylib
    /// path receives a flattened `{ "config": ProtocolConfig,
    /// "tools": { tool_name: ToolConfig, ... } }` shape so both
    /// halves come in one JSON blob.
    pub fn from_config_json(config_json: &str) -> Self {
        #[derive(serde::Deserialize, Default)]
        #[serde(deny_unknown_fields)]
        struct WireConfig {
            #[serde(default)]
            config: Option<X402ProtocolConfig>,
            #[serde(default)]
            tools: BTreeMap<String, X402ToolConfig>,
        }
        // Fail CLOSED: a present-but-malformed operator `config:` block
        // refuses this payment plugin (panic → null handle → host boot
        // rejection) instead of silently degrading to a disabled / wide-open
        // gate. An empty / absent block still yields the (disabled) default.
        let wire: WireConfig = mcpg_plugin_sdk::fail_closed_config!(config_json, WireConfig);
        match wire.config {
            Some(cfg) => Self::from_config(&cfg, wire.tools).unwrap_or_else(|err| {
                tracing::error!(
                    error = %err,
                    "payment-x402: config compile failed; loading as DISABLED"
                );
                Self::disabled()
            }),
            None => {
                tracing::warn!(
                    "payment-x402: config JSON missing top-level `config` block; loading as DISABLED"
                );
                Self::disabled()
            }
        }
    }

    /// Build challenge data for a tool that requires payment.
    fn build_challenge(&self, tool_name: &str, tool_config: &X402ToolConfig) -> Value {
        let recipient = tool_config
            .recipient
            .as_deref()
            .unwrap_or(&self.default_recipient);

        serde_json::json!({
            "protocol": "x402",
            "httpStatus": 402,
            "paymentRequirements": [{
                "scheme": "exact",
                "network": tool_config.chain_id,
                "maxAmountRequired": tool_config.charge,
                "resource": format!("tool://{}", tool_name),
                "description": format!("Payment for tool '{}'", tool_name),
                "mimeType": "application/json",
                "payTo": recipient,
                "maxTimeoutSeconds": 300,
                "asset": token_address_for_currency(&tool_config.currency, &tool_config.chain_id),
                "extra": {
                    "currency": tool_config.currency,
                    "name": format!("x402 payment for {}", tool_name),
                }
            }]
        })
    }

    /// Verify a payment credential with the facilitator.
    fn verify_payment(
        &self,
        tool_name: &str,
        tool_config: &X402ToolConfig,
        credential: &Value,
    ) -> VerifyResult {
        let payload = credential.get("payload");
        let signature = credential.get("signature").and_then(|v| v.as_str());

        if payload.is_none() || signature.is_none() {
            return VerifyResult::Failed(
                "x402 credential missing 'payload' or 'signature'".to_owned(),
            );
        }

        let recipient = tool_config
            .recipient
            .as_deref()
            .unwrap_or(&self.default_recipient);

        let verify_request = serde_json::json!({
            "payload": payload,
            "signature": signature,
            "requirements": {
                "scheme": "exact",
                "network": tool_config.chain_id,
                "maxAmountRequired": tool_config.charge,
                "payTo": recipient,
                "asset": token_address_for_currency(&tool_config.currency, &tool_config.chain_id),
            }
        });

        let verify_url = format!("{}/verify", self.facilitator_url.trim_end_matches('/'));

        match self
            .http_client
            .post(&verify_url)
            .json(&verify_request)
            .send()
        {
            Ok(response) => {
                // Security: DNS rebinding guard on facilitator response.
                if let Err(e) = mcpg_plugin_protocol::security::check_response_remote_addr(
                    response.remote_addr(),
                    false,
                ) {
                    warn!(url = %verify_url, error = %e, "x402 facilitator DNS rebinding blocked");
                    return VerifyResult::Failed(format!("x402 facilitator SSRF blocked: {e}"));
                }
                let status = response.status().as_u16();
                match response.json::<Value>() {
                    Ok(body) => {
                        if status == 200
                            && body.get("valid").and_then(|v| v.as_bool()).unwrap_or(false)
                        {
                            let tx_hash = body
                                .get("txHash")
                                .or_else(|| body.get("transaction_hash"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("facilitator-verified");
                            let receipt = serde_json::json!({
                                "x402/receipt": {
                                    "status": "success",
                                    "protocol": "x402",
                                    "network": tool_config.chain_id,
                                    "txHash": tx_hash,
                                    "amount": tool_config.charge,
                                    "currency": tool_config.currency,
                                }
                            });
                            info!(
                                tool_name = %tool_name,
                                tx_hash = %tx_hash,
                                network = %tool_config.chain_id,
                                "x402 payment verified"
                            );
                            VerifyResult::Verified(receipt)
                        } else {
                            let reason = body
                                .get("error")
                                .or_else(|| body.get("message"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("facilitator rejected payment");
                            warn!(
                                tool_name = %tool_name,
                                network = %tool_config.chain_id,
                                reason = %reason,
                                "x402 payment verification failed"
                            );
                            VerifyResult::Failed(reason.to_owned())
                        }
                    }
                    Err(e) => {
                        warn!(
                            tool_name = %tool_name,
                            error = %e,
                            "x402 facilitator response parse error"
                        );
                        VerifyResult::Failed(format!("facilitator response error: {}", e))
                    }
                }
            }
            Err(e) => {
                warn!(
                    tool_name = %tool_name,
                    facilitator = %self.facilitator_url,
                    error = %e,
                    "x402 facilitator request failed"
                );
                VerifyResult::Failed(format!("facilitator unreachable: {}", e))
            }
        }
    }
}

enum VerifyResult {
    Verified(Value),
    Failed(String),
}

// ---------------------------------------------------------------------------
// ToolGatePlugin implementation
// ---------------------------------------------------------------------------

impl SyncToolGate for X402PaymentPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        config: &Value,
    ) -> GateDecision {
        // Plugin-scoped span so traces from the x402 payment gate
        // attribute back to dev.mcpg.payment.x402.
        let _span = tracing::info_span!(
            "x402_payment_evaluate_pre",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();
        let started = std::time::Instant::now();
        let decision = self.evaluate_pre_inner(ctx, arguments, meta, config);
        let outcome = match &decision {
            GateDecision::Allow { .. } => "allow",
            GateDecision::Deny { .. } => "deny",
            GateDecision::Challenge { .. } => "challenge",
            GateDecision::PendingApproval { .. } => "pending_approval",
        };
        metrics::counter!(
            "mcpg_payment_x402_evaluations_total",
            "outcome" => outcome,
        )
        .increment(1);
        metrics::histogram!("mcpg_payment_x402_evaluate_ms")
            .record(started.elapsed().as_millis() as f64);
        decision
    }

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _arguments: &Value,
        _result: &Value,
        _duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        // x402 has no post-dispatch logic; settlement happens in
        // pre-dispatch via facilitator verify.
        GateDecision::allow()
    }
}

impl X402PaymentPlugin {
    fn evaluate_pre_inner(
        &self,
        ctx: &PluginContext,
        _arguments: &Value,
        meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        if !self.enabled {
            return GateDecision::allow();
        }

        // Payment gating applies to tool calls only — non-tool surfaces
        // are never charged.
        if ctx.surface != "tool" {
            return GateDecision::allow();
        }

        let tool_config = match self.tool_configs.get(&ctx.tool_name) {
            Some(cfg) => cfg,
            None => return GateDecision::allow(),
        };

        // Check for x402 payment credential in _meta
        let credential = meta.and_then(|m| m.get("x402/payment"));

        match credential {
            None => {
                // No credential → issue challenge
                let challenge_data = self.build_challenge(&ctx.tool_name, tool_config);
                GateDecision::Challenge {
                    http_status: 402,
                    code: X402_PAYMENT_REQUIRED_CODE,
                    message: format!(
                        "x402 payment required for tool '{}' ({} {})",
                        ctx.tool_name, tool_config.charge, tool_config.currency,
                    ),
                    challenge_data,
                }
            }
            Some(cred) => {
                // Credential present → verify with facilitator
                match self.verify_payment(&ctx.tool_name, tool_config, cred) {
                    VerifyResult::Verified(receipt) => GateDecision::allow_with_metadata(receipt),
                    VerifyResult::Failed(reason) => {
                        tracing::warn!(
                            plugin_id = PLUGIN_ID,
                            tool = %ctx.tool_name,
                            reason = %reason,
                            "x402 payment verification failed"
                        );
                        GateDecision::Deny {
                            http_status: 403,
                            code: X402_VERIFICATION_FAILED_CODE,
                            message: format!("x402 payment failed: {reason}"),
                            error_data: None,
                        }
                    }
                }
            }
        }
    }
}

/// Async trait impl — required for the gateway's path-dep usage
/// (`PaymentAwarePlugin: ToolGatePlugin` bound). Delegates to the
/// sync impl.
#[async_trait]
impl ToolGatePlugin for X402PaymentPlugin {
    fn manifest(&self) -> &PluginManifest {
        SyncToolGate::manifest(self)
    }

    async fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        config: &Value,
    ) -> GateDecision {
        SyncToolGate::evaluate_pre(self, ctx, arguments, meta, config)
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: X402PaymentPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| X402PaymentPlugin::from_config_json(cfg),
        }
    ],
}

// ---------------------------------------------------------------------------
// PaymentAwarePlugin implementation
// ---------------------------------------------------------------------------

impl PaymentAwarePlugin for X402PaymentPlugin {
    fn payment_capabilities(&self) -> Vec<PaymentCapability> {
        vec![PaymentCapability {
            protocol: PaymentProtocol::X402,
            methods: vec!["eip-712".into()],
            supports_sessions: false,
            supports_commerce: false,
            meta_prefix: "x402/".into(),
        }]
    }

    fn credential_meta_keys(&self) -> Vec<String> {
        vec!["x402/payment".into()]
    }

    fn payment_category(&self) -> PaymentCategory {
        PaymentCategory::ToolGate
    }

    fn configured_tools(&self) -> Vec<String> {
        self.tool_configs.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map currency + chain to token contract address.
/// Well-known USDC addresses on supported chains.
fn token_address_for_currency(currency: &str, chain_id: &str) -> String {
    match (currency, chain_id) {
        ("USDC", "eip155:8453") => {
            // USDC on Base
            "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_owned()
        }
        ("USDC", "eip155:42161") => {
            // USDC on Arbitrum
            "0xaf88d065e77c8cC2239327C5EDb3A432268e5831".to_owned()
        }
        ("USDC", "eip155:1") => {
            // USDC on Ethereum mainnet
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_owned()
        }
        ("ETH", _) | ("WETH", _) => {
            // Native ETH (address 0x0 or wrapped)
            "0x0000000000000000000000000000000000000000".to_owned()
        }
        _ => {
            // Unknown — return empty, facilitator will need the asset config
            String::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginClass;

    fn test_plugin() -> X402PaymentPlugin {
        let mut tool_configs = BTreeMap::new();
        tool_configs.insert(
            "crypto_api".to_owned(),
            X402ToolConfig {
                charge: "0.001".to_owned(),
                currency: "ETH".to_owned(),
                chain_id: "eip155:8453".to_owned(),
                recipient: None,
            },
        );
        tool_configs.insert(
            "premium_data".to_owned(),
            X402ToolConfig {
                charge: "0.10".to_owned(),
                currency: "USDC".to_owned(),
                chain_id: "eip155:8453".to_owned(),
                recipient: Some("0xCustomRecipient".to_owned()),
            },
        );

        X402PaymentPlugin {
            manifest: X402PaymentPlugin::make_manifest(),
            enabled: true,
            tool_configs,
            facilitator_url: "https://x402.org/facilitator".to_owned(),
            default_recipient: "0xDefaultRecipient".to_owned(),
            http_client: reqwest::blocking::Client::new(),
        }
    }

    fn test_ctx(tool_name: &str) -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-1".into(),
            session_id: None,
            tool_name: tool_name.into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    #[test]
    fn disabled_plugin_allows() {
        let plugin = X402PaymentPlugin::disabled();
        let decision = plugin.evaluate_pre(
            &test_ctx("any_tool"),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn unconfigured_tool_allows() {
        let plugin = test_plugin();
        let decision = plugin.evaluate_pre(
            &test_ctx("free_tool"),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn configured_tool_without_credential_challenges() {
        let plugin = test_plugin();
        let decision = plugin.evaluate_pre(
            &test_ctx("crypto_api"),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        match decision {
            GateDecision::Challenge {
                http_status,
                code,
                challenge_data,
                ..
            } => {
                assert_eq!(http_status, 402);
                assert_eq!(code, X402_PAYMENT_REQUIRED_CODE);
                assert_eq!(challenge_data["protocol"], "x402");
                let reqs = challenge_data["paymentRequirements"].as_array().unwrap();
                assert_eq!(reqs.len(), 1);
                assert_eq!(reqs[0]["network"], "eip155:8453");
                assert_eq!(reqs[0]["maxAmountRequired"], "0.001");
                assert_eq!(reqs[0]["payTo"], "0xDefaultRecipient");
            }
            other => panic!("expected Challenge, got: {:?}", other),
        }
    }

    #[test]
    fn custom_recipient_used_in_challenge() {
        let plugin = test_plugin();
        let decision = plugin.evaluate_pre(
            &test_ctx("premium_data"),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        match decision {
            GateDecision::Challenge { challenge_data, .. } => {
                let reqs = challenge_data["paymentRequirements"].as_array().unwrap();
                assert_eq!(reqs[0]["payTo"], "0xCustomRecipient");
                assert_eq!(reqs[0]["maxAmountRequired"], "0.10");
            }
            other => panic!("expected Challenge, got: {:?}", other),
        }
    }

    #[test]
    fn missing_payload_in_credential_denied() {
        let plugin = test_plugin();
        let meta = serde_json::json!({
            "x402/payment": {
                "signature": "0xabc"
                // missing payload
            }
        });
        let decision = plugin.evaluate_pre(
            &test_ctx("crypto_api"),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        match decision {
            GateDecision::Deny { code, message, .. } => {
                assert_eq!(code, X402_VERIFICATION_FAILED_CODE);
                assert!(message.contains("missing"), "got: {message}");
            }
            other => panic!("expected Deny, got: {:?}", other),
        }
    }

    #[test]
    fn manifest_is_correct() {
        let plugin = test_plugin();
        let m = SyncToolGate::manifest(&plugin);
        assert_eq!(m.id, "dev.mcpg.payment.x402");
        assert_eq!(m.plugin_class, PluginClass::ToolGate);
        assert_eq!(m.protocol_version, "1.0");
    }

    #[test]
    fn payment_aware_capabilities() {
        let plugin = test_plugin();
        let caps = plugin.payment_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].protocol, PaymentProtocol::X402);
        assert!(!caps[0].supports_sessions);
        assert!(!caps[0].supports_commerce);
    }

    #[test]
    fn payment_aware_configured_tools() {
        let plugin = test_plugin();
        let mut tools = plugin.configured_tools();
        tools.sort();
        assert_eq!(tools, vec!["crypto_api", "premium_data"]);
    }

    #[test]
    fn payment_aware_category() {
        let plugin = test_plugin();
        assert_eq!(plugin.payment_category(), PaymentCategory::ToolGate);
    }

    #[test]
    fn token_address_known_chains() {
        assert!(!token_address_for_currency("USDC", "eip155:8453").is_empty());
        assert!(!token_address_for_currency("USDC", "eip155:42161").is_empty());
        assert!(!token_address_for_currency("ETH", "eip155:1").is_empty());
    }

    #[test]
    fn disabled_from_empty_tools() {
        let config = X402ProtocolConfig {
            rpc_urls: BTreeMap::new(),
            facilitator_url: "https://x402.org/facilitator".into(),
            recipient_address: "0xRecipient".into(),
            http_timeout_ms: 10,
        };
        let plugin = X402PaymentPlugin::from_config(&config, BTreeMap::new()).unwrap();
        assert!(!plugin.enabled);
    }

    #[test]
    fn invalid_charge_rejected() {
        let config = X402ProtocolConfig {
            rpc_urls: BTreeMap::new(),
            facilitator_url: "https://x402.org/facilitator".into(),
            recipient_address: "0xRecipient".into(),
            http_timeout_ms: 10,
        };
        let mut tools = BTreeMap::new();
        tools.insert(
            "bad".to_owned(),
            X402ToolConfig {
                charge: "not-a-number".to_owned(),
                currency: "ETH".to_owned(),
                chain_id: "eip155:8453".to_owned(),
                recipient: None,
            },
        );
        let err = X402PaymentPlugin::from_config(&config, tools).unwrap_err();
        assert!(err.to_string().contains("invalid charge"), "got: {err}");
    }

    /// Error codes must not collide with the MCP-reserved JSON-RPC range.
    #[test]
    fn x402_codes_outside_mcp_reserved_range() {
        for code in [X402_PAYMENT_REQUIRED_CODE, X402_VERIFICATION_FAILED_CODE] {
            assert!(
                !(-32099..=-32000).contains(&code),
                "x402 error code {code} collides with MCP reserved range [-32099, -32000]"
            );
        }
    }

    /// An empty / absent operator config block yields the (disabled)
    /// default rather than failing closed — the operator opted out.
    #[test]
    fn empty_config_yields_disabled_default() {
        for cfg in ["{}", "", "   ", "null"] {
            let plugin = X402PaymentPlugin::from_config_json(cfg);
            assert!(!plugin.enabled, "empty config `{cfg}` should be disabled");
            let decision = plugin.evaluate_pre(
                &test_ctx("any_tool"),
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            );
            assert!(decision.is_allow());
        }
    }

    /// A present-but-malformed config FAILS CLOSED (panics) instead of
    /// silently degrading to a disabled / wide-open gate.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn malformed_config_fails_closed() {
        let _ = X402PaymentPlugin::from_config_json("not json");
    }

    /// An unknown / typo'd top-level config key is rejected (fail-closed):
    /// `deny_unknown_fields` turns it into a parse error, which the
    /// `fail_closed_config!` convention escalates to a panic at boot rather
    /// than silently ignoring the bad key.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_toplevel_key_rejected() {
        // `confgi` is a typo of `config`; with deny_unknown_fields the
        // whole WireConfig parse fails closed.
        let _ = X402PaymentPlugin::from_config_json(
            r#"{ "confgi": { "facilitator_url": "https://x402.org/facilitator", "recipient_address": "0xabc" }, "tools": {} }"#,
        );
    }

    /// An unknown / typo'd key inside the nested protocol `config` block is
    /// likewise rejected fail-closed.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_nested_config_key_rejected() {
        let _ = X402PaymentPlugin::from_config_json(
            r#"{ "config": { "facilitator_url": "https://x402.org/facilitator", "recipient_address": "0xabc", "facilitatorUrl": "typo" }, "tools": {} }"#,
        );
    }
}
