import fs from "fs";
import path from "path";
import yaml from "yaml";

interface ModelPrices {
  in: number;
  out: number;
}

interface CostConfig {
  prices: Record<string, ModelPrices>;
  assumptions: {
    energy_kwh_per_1k_tokens: number;
    carbon_g_co2_per_kwh: number;
  };
}

let configCache: CostConfig | null = null;

function loadConfig(): CostConfig {
  if (configCache) return configCache;
  let targetPath = path.join(process.cwd(), "config", "costs.yaml");
  if (!fs.existsSync(targetPath)) {
    targetPath = path.join(process.cwd(), "..", "config", "costs.yaml");
  }
  const file = fs.readFileSync(targetPath, "utf8");
  configCache = yaml.parse(file) as CostConfig;
  return configCache;
}

export interface CostEstimate {
  estimatedCostUsd: number;
  estimatedEnergyKwh: number;
  estimatedCarbonGrams: number;
}

export function estimateCost(model: string, tokensIn: number, tokensOut: number): CostEstimate {
  const config = loadConfig();
  const prices = config.prices[model] || { in: 0, out: 0 };
  
  // prices are per 1M tokens
  const costIn = (tokensIn / 1_000_000) * prices.in;
  const costOut = (tokensOut / 1_000_000) * prices.out;
  const totalCostUsd = costIn + costOut;

  const totalTokens = tokensIn + tokensOut;
  const energy = (totalTokens / 1000) * config.assumptions.energy_kwh_per_1k_tokens;
  const carbon = energy * config.assumptions.carbon_g_co2_per_kwh;

  return {
    estimatedCostUsd: totalCostUsd,
    estimatedEnergyKwh: energy,
    estimatedCarbonGrams: carbon,
  };
}
