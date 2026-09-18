/** Error codes the gateway itself emits for security-gate outcomes. */
export type GatewayErrorCode =
  | "AEGIS_ENGINE_UNAVAILABLE"
  | "CREDENTIAL_LEAK_PREVENTED"
  | "PROMPT_INJECTION_BLOCKED"
  | "AEGIS_POLICY_BLOCKED"
  | "AEGIS_PROVIDER_UNAVAILABLE";

export function buildErrorPayload(code: string, message: string, request_id: string) {
  return {
    error: {
      code,
      message,
      request_id,
    },
  };
}
