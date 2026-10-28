/** Well-known networks and USDC deployments (checked against Circle's published addresses). */
export interface KnownAsset { symbol: string; decimals: number; network: string; eip712?: { name: string; version: string } }
const A = (address: string, network: string, eip712?: { name: string; version: string }): [string, KnownAsset] => [address.toLowerCase(), { symbol: "USDC", decimals: 6, network, eip712 }];
export const KNOWN_ASSETS = new Map<string, KnownAsset>([
  A("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "eip155:8453", { name: "USD Coin", version: "2" }),
  A("0x036CbD53842c5426634e7929541eC2318f3dCF7e", "eip155:84532", { name: "USDC", version: "2" }),
  A("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "eip155:1", { name: "USD Coin", version: "2" }),
  A("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "eip155:137", { name: "USD Coin", version: "2" }),
  A("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "eip155:42161", { name: "USD Coin", version: "2" }),
  A("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "eip155:10", { name: "USD Coin", version: "2" }),
  ["epjfwdd5aufqssqem2qn1xzybapc8g4weggkzwytdt1v", { symbol: "USDC", decimals: 6, network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" }],
]);
export const TESTNETS = new Set(["eip155:84532", "eip155:11155111", "eip155:80002", "eip155:421614", "eip155:11155420", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z", "base-sepolia", "solana-devnet", "sepolia"]);
export const V1_NETWORKS = new Set(["base", "base-sepolia", "ethereum", "sepolia", "polygon", "polygon-amoy", "avalanche", "avalanche-fuji", "solana", "solana-devnet", "iotex", "sei", "peaq", "abstract"]);
export const CAIP2 = /^[a-z0-9-]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
