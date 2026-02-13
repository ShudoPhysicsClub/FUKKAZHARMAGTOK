// ============================================================
// BTR (Buturi Coin) - 共通型定義
// ============================================================

// --- パケット ---

export const DELIMITER = '\nLINE_BREAK\n';

export interface Packet {
  type: string;
  data?: any;
  timestamp?: number;
}

// --- ブロック ---

export interface Block {
  height: number;
  previousHash: string;
  timestamp: number;
  nonce: number;
  difficulty: number;
  miner: string;
  reward: number;
  transactions: Transaction[];
  hash: string;
}

// --- トランザクション ---

export interface Transaction {
  type: 'transfer' | 'create_token' | 'token_transfer' | 'swap' | 'rename_token';
  token: string;
  from: string;
  publicKey: string;
  to?: string;
  amount?: number;
  fee: number;
  nonce: number;
  timestamp: number;
  signature: string;
  data?: TransactionData;
}

export interface TransactionData {
  name?: string;
  symbol?: string;
  totalSupply?: number;
  poolRatio?: number;
  distribution?: 'creator' | 'mining' | 'split' | 'airdrop';
  tokenIn?: string;
  tokenOut?: string;
  amountIn?: number;
  minAmountOut?: number;
  newName?: string;
}

// --- アカウント ---

export interface Account {
  address: string;
  balance: number;
  nonce: number;
  tokens: Record<string, number>;
}

// --- トークン ---

export interface TokenInfo {
  address: string;
  symbol: string;
  name: string;
  creator: string;
  createdAt: number;
  totalSupply: number;
  poolRatio: number;
  distribution: 'creator' | 'mining' | 'split' | 'airdrop';
}

// --- 権限 ---

export type Role = 'root' | 'member';

export interface TrustedKey {
  publicKey: string;
  role: Role;
  addedBy: string;
  signature: string;
}

export interface TrustedKeysFile {
  keys: TrustedKey[];
}

// --- seeds.json ---

export interface SeedEntry {
  host: string;
  priority: number;
  publicKey: string;
}

export interface SeedsFile {
  seeds: SeedEntry[];
  signature: string;
}

// --- アップデート ---

export interface UpdatePackage {
  version: string;
  code: string;
  hash: string;
  signer: string;
  signature: string;
}

// --- ジェネシスブロック ---

export interface GenesisConfig {
  name: string;
  symbol: string;
  tokenAddress: string;
  totalSupply: number;
  blockTime: number;
  blockReward: { min: number; max: number };
  gasFee: number;
  tokenCreationFee: number;
  tokenRenameFee: number;
  timestampTolerance: number;
  maxBlockSize: number;
  admin: {
    publicKey: string;
    address: string;
  };
}

export interface GenesisBlock extends Block {
  config: GenesisConfig;
  message: string;
}

// --- ノード情報 ---

export interface NodeInfo {
  id: string;
  host?: string;
  connectedAt: number;
  lastPing: number;
  chainHeight: number;
  difficulty?: number;
}