import fs from "fs";
import path from "path";
import yaml from "yaml";
import type { AegisMessage } from "../types/aegis";

interface RouteConfig {
  provider: string;
  model: string;
  failover?: string[];
}

interface RoutingConfig {
  routes: {
    low: RouteConfig;
    medium: RouteConfig;
    high: RouteConfig;
  };
}

let configCache: RoutingConfig | null = null;

function loadConfig(): RoutingConfig {
  if (configCache) return configCache;
  const configPath = path.join(process.cwd(), "..", "config", "routing.yaml");
  // Next.js sets process.cwd() to frontend. 
  // Let's try to resolve it relative to __dirname for reliability if possible.
  let targetPath = path.join(process.cwd(), "config", "routing.yaml");
  if (!fs.existsSync(targetPath)) {
    targetPath = path.join(process.cwd(), "..", "config", "routing.yaml");
  }
  const file = fs.readFileSync(targetPath, "utf8");
  configCache = yaml.parse(file) as RoutingConfig;
  return configCache;
}

export function classifyComplexity(messages: AegisMessage[]): "low" | "medium" | "high" {
  let totalLength = 0;
  let hasCodeBlock = false;
  let hasReasoningKeywords = false;
  let hasMultiStep = false;

  const reasoningKeywords = ["think", "step by step", "analyze", "explain why", "evaluate", "compare"];
  const multiStepKeywords = ["first", "then", "finally", "1.", "2.", "3."];

  for (const msg of messages) {
    if (msg.role !== "user") continue;
    const content = msg.content;
    totalLength += content.length;

    if (content.includes("```")) {
      hasCodeBlock = true;
    }

    const lower = content.toLowerCase();
    for (const kw of reasoningKeywords) {
      if (lower.includes(kw)) hasReasoningKeywords = true;
    }

    let stepMatches = 0;
    for (const kw of multiStepKeywords) {
      if (lower.includes(kw)) stepMatches++;
    }
    if (stepMatches >= 2) hasMultiStep = true;
  }

  // Very rough heuristic for tokens (4 chars ~ 1 token)
  const estimatedTokens = totalLength / 4;

  if (estimatedTokens > 1000 || hasCodeBlock || (hasReasoningKeywords && hasMultiStep)) {
    return "high";
  }
  if (estimatedTokens > 250 || hasReasoningKeywords || hasMultiStep) {
    return "medium";
  }
  return "low";
}

export function getRouteForMessages(messages: AegisMessage[] | null): RouteConfig {
  const complexity = messages ? classifyComplexity(messages) : "low";
  const config = loadConfig();
  return config.routes[complexity];
}
