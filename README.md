# x402 Crypto Micropayments — `dev.mcpg.payment.x402`

> class `tool_gate` · `native` · package `mcpg-plugin-payment-x402` · artifact `libmcpg_plugin_payment_x402.so` · BUSL-1.1

Per-call crypto micropayment gate for MCP tools, speaking the x402 protocol. A
call to a priced tool that arrives without a payment credential is answered with
an HTTP 402 challenge carrying machine-readable payment requirements — network,
asset, amount, and recipient — and a call that carries one is verified against an
x402 facilitator before the tool runs. Reach for it when you want to charge
agents per tool call in stablecoin without running an invoicing or account
system: there is no session, no cart, and no state to keep between calls.

## What it does
- Prices tools individually. A tool absent from the `tools` map is never gated,
  and non-tool surfaces are never charged.
- Answers an unpaid call with `Challenge` — HTTP 402, JSON-RPC code `-33060` —
  whose data holds an x402 `paymentRequirements` entry: `scheme: "exact"`, the
  chain as `network`, the charge as `maxAmountRequired`, `resource:
  "tool://<name>"`, the recipient as `payTo`, the token contract as `asset`, and
  `maxTimeoutSeconds: 300`.
- Reads the caller's payment credential from `_meta["x402/payment"]` and requires
  both a `payload` and a `signature` before contacting anyone.
- Verifies by POSTing the credential and the tool's requirements to
  `<facilitator_url>/verify`, and treats the payment as good only when the
  facilitator answers HTTP 200 **and** `valid: true`.
- Attaches a receipt on success as decision metadata under `x402/receipt`,
  carrying the facilitator's transaction hash, network, amount, and currency.
- Denies a failed or unverifiable payment with HTTP 403 and JSON-RPC code
  `-33061`, quoting the facilitator's reason.
- Declares the `network_outbound` capability, consumed by the facilitator call.

## Configuration
Loaded from the flat top-level `plugins:` list. The `config:` block has two
halves: a `config` sub-object for protocol-wide settings, and a `tools` map whose
keys are the tool names to price. With no `tools` entries the plugin loads
disabled and allows every call.

```yaml
plugins:
  - id: dev.mcpg.payment.x402
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_payment_x402.so }
    # or, platform-agnostic — the gateway resolves the artifact for its own
    # os/arch/libc at boot:
    # source: { oci: ghcr.io/mcpg-dev/source-code/plugins/payment-x402:protocol-1 }
    granted_capabilities: [network_outbound]   # required — the facilitator call
    config:
      config:
        facilitator_url: https://x402.org/facilitator   # required
        recipient_address: "0xRecipient..."             # required
        http_timeout_ms: 10000
      tools:
        premium.query:
          charge: "0.10"                # required, per call
          currency: USDC
          chain_id: "eip155:8453"       # Base mainnet
        crypto.stream:
          charge: "0.001"
          currency: ETH
          recipient: "0xOther..."       # per-tool override
```

Protocol settings, under `config.config`:

| Field | Type | Default | Description |
|---|---|---|---|
| `facilitator_url` | string | required | Base URL of the x402 facilitator; the plugin POSTs to `<url>/verify`. |
| `recipient_address` | string | required | Default payment recipient for every priced tool. |
| `http_timeout_ms` | integer | `10` | Facilitator request timeout, in milliseconds. Set this to a realistic value for your facilitator — the default is 10 milliseconds. |
| `rpc_urls` | map<string,string> | `{}` | Accepted by the schema. Chain access happens at the facilitator, so these are not dialled by the plugin. |

Per-tool settings, under `config.tools.<tool name>`:

| Field | Type | Default | Description |
|---|---|---|---|
| `charge` | string | required | Amount per call, as a decimal string. Must parse as a finite number greater than zero or the config is rejected. |
| `currency` | string | `"USDC"` | Token symbol quoted in the challenge and the receipt. |
| `chain_id` | string | `"eip155:8453"` | Chain identifier, sent verbatim as the x402 `network` (the default is Base mainnet). |
| `recipient` | string | unset | Overrides `recipient_address` for this tool. |

Unknown fields are rejected, at the wire level and inside both nested blocks.

The plugin declares the `network_outbound` capability, so the entry has to grant
it: a packaged load (`source.path` pointing at a `.zip`, or `source.oci`) is
refused at boot when `granted_capabilities` does not list it.

**Asset resolution.** The `asset` in the challenge is derived from
`(currency, chain_id)`: USDC on `eip155:8453`, `eip155:42161`, and `eip155:1`
resolve to their canonical contract addresses, `ETH` and `WETH` resolve to the
zero address, and any other pair yields an empty `asset` — the facilitator then
has to know the token itself.

## Security
**Verification is the only thing that grants a call.** A credential is accepted
only when the facilitator returns HTTP 200 with `valid: true`; a non-200, a
malformed body, an unreachable facilitator, or a missing `payload`/`signature`
all deny. The gate never trusts the credential on its own.

**The gate is stateless, so replay protection is the facilitator's job.** No
record of spent credentials is kept: every call re-submits whatever the client
presented and takes the facilitator's answer. Choose a facilitator that rejects a
credential it has already settled.

**Responses from private addresses are refused.** Every facilitator response
passes a DNS-rebinding check that rejects a reply arriving from a private or
loopback address, so a hostile DNS answer cannot point the verify call at
something inside your network.

**Config failure modes are asymmetric — know which one you are in.** Malformed
JSON, an unknown key, or a `config` block that omits `facilitator_url` or
`recipient_address` refuses the plugin at boot, so a typo cannot open the gate. An
empty or absent `config:` block, a block with no top-level `config`, and a
structurally valid block that fails validation (an empty `facilitator_url` or
`recipient_address`, or an unparseable `charge`) all load the plugin **disabled**
— which allows every call. Treat a startup log line naming a disabled payment
gate as a production incident, and assert on it in deployment checks.

**Error codes stay clear of the MCP reserved range.** `-33060` and `-33061` sit
outside `-32099..=-32000`, so they never collide with spec-assigned JSON-RPC
codes.

## Observability
- `mcpg_payment_x402_evaluations_total{outcome}` — `allow`, `deny`, `challenge`,
  or `pending_approval`.
- `mcpg_payment_x402_evaluate_ms` — pre-dispatch evaluation latency.

Each evaluation opens an `x402_payment_evaluate_pre` tracing span tagged with the
plugin id and tool name. Verified payments log at INFO with the transaction hash;
rejections log at WARN with the facilitator's reason.

## Build
The `cdylib-export` feature gates the `mcpg_plugin_register` export. It is on by
default for a standalone build and switched off when the crate is linked as a
path dependency alongside other plugins, since several `mcpg_plugin_register`
symbols collide at link time:

```bash
cargo build -p mcpg-plugin-payment-x402 --features cdylib-export --release   # → target/release/libmcpg_plugin_payment_x402.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes, loading, and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
- Sibling payment gates: `libs/plugins/payment/acp`, `libs/plugins/payment/ucp`,
  `libs/plugins/payment/mpp`
- Licence: BUSL-1.1 — see [`LICENSE`](./LICENSE) for the Additional Use Grant
  that governs production use.
