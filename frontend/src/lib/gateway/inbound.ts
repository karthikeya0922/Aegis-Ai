/**
 * Inbound request parsing for /v1/chat/completions.
 *
 * The client's messages are handed out ONLY inside an `InboundMessages` holder,
 * which the scan gate empties exactly once. After the gate runs, nothing in the
 * request can read the original messages again — `take()` throws.
 */

import { z } from "zod";
import type { AegisMessage } from "@aegis/types/aegis";
import type { ProviderParams } from "./provider";

export class InboundMessages {
  #messages: AegisMessage[] | null;

  constructor(messages: AegisMessage[]) {
    this.#messages = messages;
  }

  /** Returns the original messages and drops this holder's reference. Single use. */
  take(): AegisMessage[] {
    const messages = this.#messages;
    if (messages === null) {
      throw new Error("Inbound messages were already consumed by the scan gate");
    }
    this.#messages = null;
    return messages;
  }
}

export const MAX_PAYLOAD_SIZE = 256 * 1024; // 256KB

// Messages must be plain text the engine can scan. Anything richer (content-part
// arrays, tool messages) is rejected rather than forwarded partially unscanned.
const chatCompletionSchema = z
  .object({
    model: z.string(),
    messages: z
      .array(
        z.object({
          role: z.enum(["system", "user", "assistant"]),
          content: z.string(),
        }),
      )
      .min(1),
    stream: z.boolean().optional(),
    temperature: z.number().optional(),
  })
  .passthrough();

export type InboundParseResult =
  | { ok: true; messages: InboundMessages; params: ProviderParams }
  | { ok: false; status: 400 | 413; code: string; message: string };

/**
 * Reads and validates the request body. The raw text, parsed JSON and zod output
 * are all local to this function, so the only surviving reference to the original
 * messages is the returned `InboundMessages` holder.
 */
export async function readChatRequest(req: Request): Promise<InboundParseResult> {
  const text = await req.text();

  if (new TextEncoder().encode(text).length > MAX_PAYLOAD_SIZE) {
    return { ok: false, status: 413, code: "payload_too_large", message: "Payload exceeds 256KB limit" };
  }
  if (!text) {
    return { ok: false, status: 400, code: "missing_body", message: "Request body is required" };
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return { ok: false, status: 400, code: "invalid_json", message: "Invalid JSON payload" };
  }

  const validation = chatCompletionSchema.safeParse(body);
  if (!validation.success) {
    return { ok: false, status: 400, code: "validation_error", message: "Invalid request body format" };
  }

  const { messages, ...params } = validation.data;
  return { ok: true, messages: new InboundMessages(messages), params };
}
