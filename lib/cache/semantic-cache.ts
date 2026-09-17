import { createClient } from "redis";
import fs from "fs";
import path from "path";
import yaml from "yaml";
import { estimateCost } from "../cost";
import type { AegisMessage, Detection, AegisAction } from "../types/aegis";

export interface GatewayPrompt {
  action: AegisAction;
  detections: Detection[];
  sanitized_messages: AegisMessage[];
}

interface CacheConfig {
  embedding: {
    provider: string;
    ollama?: {
      base_url: string;
      model: string;
    };
    openai?: {
      base_url: string;
      model: string;
      api_key_env?: string;
    };
  };
}

let configCache: CacheConfig | null = null;
function loadConfig(): CacheConfig {
  if (configCache) return configCache;
  let targetPath = path.join(process.cwd(), "config", "cache.yaml");
  if (!fs.existsSync(targetPath)) {
    targetPath = path.join(process.cwd(), "..", "config", "cache.yaml");
  }
  const file = fs.readFileSync(targetPath, "utf8");
  configCache = yaml.parse(file) as CacheConfig;
  return configCache;
}

const redisClient = createClient({
  url: process.env.REDIS_URL || "redis://localhost:6379"
});
redisClient.on("error", (err) => console.error("Redis Client Error", err));

let isConnected = false;
let connectionPromise: Promise<void> | null = null;

async function ensureRedis() {
  if (process.env.NODE_ENV === "test") return;
  if (isConnected) return;
  if (!connectionPromise) {
    connectionPromise = redisClient.connect().then(async () => {
      isConnected = true;
      try {
        await redisClient.ft.create("idx:semantic_cache", {
          embedding: {
            type: "VECTOR",
            ALGORITHM: "FLAT",
            TYPE: "FLOAT32",
            DIM: 768,
            DISTANCE_METRIC: "COSINE"
          },
          response: { type: "TEXT" },
          tokensOut: { type: "NUMERIC" },
          tenant: { type: "TAG" }
        }, {
          ON: "HASH",
          PREFIX: "aegis:cache:"
        });
      } catch (e: any) {
        if (!e.message.includes("Index already exists")) {
          console.error("Redis FT.CREATE error", e);
        }
      }
    }).catch(err => {
      connectionPromise = null;
      throw err;
    });
  }
  await connectionPromise;
}

async function getEmbedding(text: string): Promise<number[]> {
  const config = loadConfig();
  if (config.embedding.provider === "ollama") {
    const oConf = config.embedding.ollama!;
    const res = await fetch(`${oConf.base_url}/api/embeddings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: oConf.model, prompt: text })
    });
    const data = await res.json();
    return data.embedding;
  } else if (config.embedding.provider === "openai") {
    const oConf = config.embedding.openai!;
    const envKey = oConf.api_key_env || "OPENAI_API_KEY";
    const apiKey = process.env[envKey];
    const res = await fetch(`${oConf.base_url}/embeddings`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      },
      body: JSON.stringify({ model: oConf.model, input: text })
    });
    const data = await res.json();
    return data.data[0].embedding;
  }
  throw new Error("Unknown embedding provider");
}

function float32Buffer(arr: number[]) {
  return Buffer.from(new Float32Array(arr).buffer);
}

export interface CacheTelemetry {
  cache_hit: boolean;
  similarity?: number;
  latency_ms?: number;
  estimated_cost_avoided?: number;
}

export interface CacheResult {
  hit: boolean;
  response?: string;
  telemetry: CacheTelemetry;
}

export async function checkCache(
  messages: readonly AegisMessage[],
  action: AegisAction,
  categories: string[],
  model: string,
  noCacheHeader: boolean,
  tenant: string
): Promise<CacheResult> {
  const start = Date.now();
  if (noCacheHeader || process.env.NODE_ENV === "test") {
    return { hit: false, telemetry: { cache_hit: false } };
  }

  // Never cache or retrieve if warning/blocking or secrets detected
  if (action === "warn" || action === "block") {
    return { hit: false, telemetry: { cache_hit: false } };
  }
  
  if (categories.some(c => c.startsWith("SECRET"))) {
    return { hit: false, telemetry: { cache_hit: false } };
  }

  // MUST USE SANITIZED MESSAGES!
  const textToEmbed = messages
    .filter((m: AegisMessage) => m.role === "user")
    .map((m: AegisMessage) => m.content)
    .join("\n");

  if (!textToEmbed) {
    return { hit: false, telemetry: { cache_hit: false } };
  }

  let embedding: number[];
  let threshold: number;
  let radius: number;
  try {
    await ensureRedis();
    embedding = await getEmbedding(textToEmbed);
    threshold = parseFloat(process.env.AEGIS_CACHE_THRESHOLD || "0.92");
    radius = 1 - threshold;
  } catch (e) {
    console.error("Semantic cache initialization/embedding error:", e);
    return { hit: false, telemetry: { cache_hit: false } };
  }

  try {
    const results = await redisClient.ft.search(
      "idx:semantic_cache",
      `(@tenant:{${tenant.replace(/[-]/g, "\\-")}})=>[KNN 1 @embedding $BLOB AS dist]`,
      {
        PARAMS: {
          BLOB: float32Buffer(embedding)
        },
        RETURN: ["response", "tokensOut", "dist"],
        SORTBY: "dist",
        DIALECT: 2,
        LIMIT: { from: 0, size: 1 }
      }
    );

    if (results.total > 0) {
      const doc = results.documents[0].value;
      const distance = parseFloat(doc.dist as string);
      const similarity = 1 - distance;

      if (similarity >= threshold) {
        // HIT!
        const latency = Date.now() - start;
        // Cost avoided: approx tokensIn = textToEmbed length / 4
        const estimatedTokensIn = Math.ceil(textToEmbed.length / 4);
        const tokensOut = parseInt((doc.tokensOut as string) || "100", 10);
        
        const costEstimate = estimateCost(model, estimatedTokensIn, tokensOut);

        return {
          hit: true,
          response: doc.response as string,
          telemetry: {
            cache_hit: true,
            similarity,
            latency_ms: latency,
            estimated_cost_avoided: costEstimate.estimatedCostUsd
          }
        };
      }
    }
  } catch (e) {
    console.error("Semantic cache search error:", e);
  }

  return { hit: false, telemetry: { cache_hit: false } };
}

export async function storeCache(
  messages: readonly AegisMessage[],
  action: AegisAction,
  categories: string[],
  responseContent: string,
  tokensOut: number,
  tenant: string
) {
  if (process.env.NODE_ENV === "test") return;
  if (action === "warn" || action === "block") {
    return;
  }
  if (categories.some(c => c.startsWith("SECRET"))) {
    return;
  }

  const textToEmbed = messages
    .filter((m: AegisMessage) => m.role === "user")
    .map((m: AegisMessage) => m.content)
    .join("\n");
  
  if (!textToEmbed) return;

  await ensureRedis();
  
  try {
    const embedding = await getEmbedding(textToEmbed);
    const id = `aegis:cache:${Date.now()}:${Math.random().toString(36).substring(7)}`;
    
    // We must pass the buffer as a raw blob. Node Redis handles Buffers properly if we use the generic client or HSET
    await redisClient.hSet(id, {
      embedding: float32Buffer(embedding),
      response: responseContent,
      tokensOut: tokensOut.toString(),
      tenant
    });
  } catch (e) {
    console.error("Semantic cache store error:", e);
  }
}
