import { Connection, PublicKey, Keypair, clusterApiUrl } from '@solana/web3.js';
import * as bs58 from 'bs58';
import crypto from 'crypto';
import fs from 'fs';
import readline from 'readline-sync';

// Configuration
const SERVER_URL = 'https://solana-server-ud9a.onrender.com';
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const connection = new Connection(SOLANA_RPC_URL, 'confirmed');

// ============================================================================
// TYPES
// ============================================================================

interface ValidatorInfo {
  votePubkey: string;
  nodePubkey: string;
  activatedStake: number;
  commission: number;
  lastVote: number;
  description?: string;
}

interface StakingPeriod {
  label: string;
  value: number;
  description: string;
}

interface SessionKeyResponse {
  success: boolean;
  sessionId: string;
  expiresIn: number;
}

interface StakeActivation {
  state: 'active' | 'inactive' | 'activating' | 'deactivating';
  activationEpoch?: number;
  deactivationEpoch?: number;
}

interface DelegationResponse {
  success: boolean;
  transactionSignature?: string;
  stakeAccountAddress?: string;
  delegatedTo?: string;
  lamportsDelegated?: number;
  stakingPeriod?: number;
  stakeActivation?: StakeActivation;
  error?: string;
  details?: string;
}

interface DelegationRequest {
  sessionId: string;
  encryptedPrivateKey: string;
  iv: string;
  publicKey: string;
  voteAccountAddress: string;
  lamportsToDelegate: number;
  stakingPeriod: number;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Make HTTP request to server
 */
async function makeRequest<T>(
  endpoint: string,
  method: 'GET' | 'POST' = 'GET',
  body?: any
): Promise<T> {
  try {
    const options: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(`${SERVER_URL}${endpoint}`, options);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${response.statusText} - ${errorText}`);
    }

    return (await response.json()) as T;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Request to ${endpoint} failed: ${errorMsg}`);
  }
}

/**
 * Encrypt private key using AES-256-GCM with provided session ID
 */
function encryptPrivateKey(privateKeyBuffer: Buffer, sessionId: string): {
  encryptedKey: string;
  iv: string;
} {
  try {
    // Generate random 16-byte IV
    const iv = crypto.randomBytes(16);

    // Derive encryption key from sessionId using SHA-256 (matching server's derivation)
    const encryptionKey = crypto.createHash('sha256').update(sessionId).digest();

    // Create cipher with AES-256-GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);

    // Encrypt private key
    const encrypted = Buffer.concat([cipher.update(privateKeyBuffer), cipher.final()]);

    // Append auth tag
    const authTag = cipher.getAuthTag();
    const ciphertext = Buffer.concat([encrypted, authTag]);

    // Return base64 encoded
    return {
      encryptedKey: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
    };
  } catch (error) {
    throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Parse private key from various formats according to official Solana docs
 */
function parsePrivateKey(input: string): Buffer {
  const trimmed = input.trim();

  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    try {
      const jsonArray = JSON.parse(trimmed);
      if (Array.isArray(jsonArray) && jsonArray.length === 64) {
        if (jsonArray.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
          const buffer = Buffer.from(jsonArray);
          return buffer;
        }
      }
      throw new Error('JSON array must contain exactly 64 integers between 0-255');
    } catch (e) {
      throw new Error(
        `Failed to parse as JSON array: ${e instanceof Error ? e.message : 'Invalid JSON'}`
      );
    }
  }

  if (/^[0-9a-fA-F]+$/.test(trimmed)) {
    try {
      if (trimmed.length % 2 !== 0) {
        throw new Error(`Hex string must have even length, got ${trimmed.length}`);
      }

      if (trimmed.length === 64) {
        const seedBuffer = Buffer.from(trimmed, 'hex');
        const keypair = Keypair.fromSeed(seedBuffer);
        return keypair.secretKey;
      } else if (trimmed.length === 128) {
        const buffer = Buffer.from(trimmed, 'hex');
        return buffer;
      } else {
        throw new Error(
          `Invalid hex length: expected 64 chars (32-byte seed) or 128 chars (64-byte secret), got ${trimmed.length}`
        );
      }
    } catch (e) {
      throw new Error(`Failed to parse as hex: ${e instanceof Error ? e.message : 'Invalid hex string'}`);
    }
  }

  if (/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(trimmed)) {
    try {
      const buffer = Buffer.from(bs58.decode(trimmed));
      if (buffer.length !== 64) {
        throw new Error(`Invalid base58 decoded length: expected 64 bytes, got ${buffer.length}`);
      }
      return buffer;
    } catch (e) {
      throw new Error(`Failed to parse as base58: ${e instanceof Error ? e.message : 'Invalid base58 string'}`);
    }
  }

  throw new Error(
    'Unrecognized private key format. Supported formats:\n' +
      '  • JSON Array: [0, 1, 2, ...] (64 integers from Solana CLI file)\n' +
      '  • Hex Seed: "a1b2c3..." (64 hex characters = 32-byte seed)\n' +
      '  • Hex Secret: "a1b2c3..." (128 hex characters = 64-byte secret key)\n' +
      '  • Base58 String: "5KXwfr..." (standard wallet encoding)'
  );
}

/**
 * Load private key from file or stdin
 */
function loadPrivateKey(): Buffer {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║              Load Your Private Key                             ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  const choice = readline.keyInSelect(['Enter as text', 'Load from file'], 'Choose method: ');

  let privateKeyBuffer: Buffer;

  if (choice === 0) {
    const privateKeyStr = readline.question(
      'Paste your private key in any of these formats:\n' +
        '  • JSON Array: [0, 1, 2, ...] (from Solana CLI keypair file)\n' +
        '  • Hex Seed: a1b2c3d4... (64 hex chars, 32-byte seed)\n' +
        '  • Hex Secret: a1b2c3d4... (128 hex chars, 64-byte key)\n' +
        '  • Base58 String: 5KXwfr...\n\n' +
        'Private key: ',
      {
        hideEchoBack: true,
      }
    );

    try {
      privateKeyBuffer = parsePrivateKey(privateKeyStr);
    } catch (error) {
      throw new Error(`Invalid private key: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  } else if (choice === 1) {
    const filePath = readline.question('Enter path to private key file: ');

    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const fileContent = fs.readFileSync(filePath, 'utf-8');

    try {
      privateKeyBuffer = parsePrivateKey(fileContent);
    } catch (error) {
      throw new Error(
        `Invalid private key in file: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  } else {
    throw new Error('Invalid choice');
  }

  try {
    const keypair = Keypair.fromSecretKey(privateKeyBuffer);
    console.log(`\n✓ Loaded private key for: ${keypair.publicKey.toString()}\n`);
  } catch (error) {
    throw new Error(
      `Invalid private key - failed to derive keypair: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }

  return privateKeyBuffer;
}

/**
 * Fetch and display available validators
 */
async function selectValidator(): Promise<string> {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║          Fetching Available Validators                        ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  try {
    const voteAccounts = await connection.getVoteAccounts();

    if (!voteAccounts.current || voteAccounts.current.length === 0) {
      throw new Error('No validators found on cluster');
    }

    const validators: ValidatorInfo[] = voteAccounts.current.slice(0, 20).map((validator) => ({
      votePubkey: validator.votePubkey,
      nodePubkey: validator.nodePubkey,
      activatedStake: validator.activatedStake || 0,
      commission: validator.commission || 0,
      lastVote: validator.lastVote || 0,
    }));

    console.log(`Found ${voteAccounts.current.length} validators. Showing top 20:\n`);

    validators.forEach((validator, index) => {
      const stakeInSol = validator.activatedStake / 1e9;
      console.log(
        `${index + 1}. ${validator.votePubkey.substring(0, 8)}... | ` +
          `Stake: ${stakeInSol.toFixed(2)}◎ | ` +
          `Commission: ${validator.commission}% | ` +
          `Last Vote: ${validator.lastVote}`
      );
    });

    const selectedIndex = readline.keyInSelect(
      validators.map((v) => `${v.votePubkey.substring(0, 12)}... (${(v.activatedStake / 1e9).toFixed(2)}◎)`),
      '\nSelect validator: '
    );

    if (selectedIndex === -1) {
      throw new Error('No validator selected');
    }

    const selectedValidator = validators[selectedIndex];
    console.log(`\n✓ Selected validator: ${selectedValidator.votePubkey}\n`);

    return selectedValidator.votePubkey;
  } catch (error) {
    throw new Error(`Failed to fetch validators: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Fetch and display available staking periods
 */
async function selectStakingPeriod(): Promise<number> {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║          Fetching Staking Periods                             ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  try {
    const response = await makeRequest<{
      success: boolean;
      periods: StakingPeriod[];
    }>('/api/staking-periods', 'GET');

    if (!response.success || !response.periods) {
      throw new Error('Failed to fetch staking periods');
    }

    const periods = response.periods;

    console.log('Available staking periods:\n');
    periods.forEach((period, index) => {
      console.log(`${index + 1}. ${period.label}`);
      console.log(`   ${period.description}\n`);
    });

    const selectedIndex = readline.keyInSelect(
      periods.map((p) => p.label),
      'Select staking period: '
    );

    if (selectedIndex === -1) {
      throw new Error('No staking period selected');
    }

    const selectedPeriod = periods[selectedIndex];
    console.log(`\n✓ Selected period: ${selectedPeriod.label}\n`);

    return selectedPeriod.value;
  } catch (error) {
    throw new Error(`Failed to fetch staking periods: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Get amount of SOL to delegate
 */
function getStakingAmount(): number {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║          Staking Amount                                        ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  const solAmount = readline.questionFloat('Enter amount of SOL to stake (e.g., 0.1): ');

  if (solAmount <= 0) {
    throw new Error('Staking amount must be greater than 0');
  }

  const lamports = Math.floor(solAmount * 1e9);

  console.log(`\n✓ Staking ${solAmount}◎ (${lamports} lamports)\n`);

  return lamports;
}

// ============================================================================
// DELEGATION FLOW
// ============================================================================

/**
 * Handle delegation request and process server response
 */
async function delegateStake(
  sessionId: string,
  privateKeyBuffer: Buffer,
  publicKey: string,
  voteAccountAddress: string,
  lamportsToDelegate: number,
  stakingPeriod: number
): Promise<void> {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║          Encrypting Private Key                               ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  console.log('Encrypting private key with AES-256-GCM...');

  let encryptedData: { encryptedKey: string; iv: string };
  try {
    encryptedData = encryptPrivateKey(privateKeyBuffer, sessionId);
    console.log('✓ Private key encrypted\n');
  } catch (error) {
    throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║          Sending Delegation Request                           ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  const delegationRequest: DelegationRequest = {
    sessionId: sessionId,
    encryptedPrivateKey: encryptedData.encryptedKey,
    iv: encryptedData.iv,
    publicKey: publicKey,
    voteAccountAddress: voteAccountAddress,
    lamportsToDelegate: lamportsToDelegate,
    stakingPeriod: stakingPeriod,
  };

  console.log('[v0] Full request object:');
  console.log('[v0]', JSON.stringify({
    sessionId: delegationRequest.sessionId ? 'SET' : 'EMPTY',
    encryptedPrivateKey: delegationRequest.encryptedPrivateKey ? 'SET' : 'EMPTY',
    iv: delegationRequest.iv ? 'SET' : 'EMPTY',
    publicKey: delegationRequest.publicKey,
    voteAccountAddress: delegationRequest.voteAccountAddress,
    lamportsToDelegate: delegationRequest.lamportsToDelegate,
    stakingPeriod: delegationRequest.stakingPeriod,
  }, null, 2));

  console.log('\nSending encrypted private key and delegation parameters to server...');

  let delegationResponse: DelegationResponse;
  try {
    delegationResponse = await makeRequest<DelegationResponse>('/api/delegate-stake', 'POST', delegationRequest);
  } catch (error) {
    throw new Error(`Delegation request failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  if (!delegationResponse.success) {
    throw new Error(`Delegation failed: ${delegationResponse.error} - ${delegationResponse.details}`);
  }

  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║          Delegation Successful!                               ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  console.log(`Transaction Signature: ${delegationResponse.transactionSignature}`);
  console.log(`\n→ View on explorer: https://explorer.solana.com/tx/${delegationResponse.transactionSignature}?cluster=mainnet-beta\n`);
}

// ============================================================================
// MAIN FLOW
// ============================================================================

async function main() {
  try {
    console.log(`
╔════════════════════════════════════════════════════════════════╗
║          Solana Delegation Staking Client                      ║
╚════════════════════════════════════════════════════════════════╝

Network: ${SOLANA_RPC_URL}
Server: ${SERVER_URL}
    `);

    console.log('Checking server connection...');
    try {
      const health = await makeRequest<{ success: boolean }>('/api/health', 'GET');
      if (!health.success) {
        throw new Error('Server is not healthy');
      }
      console.log('✓ Connected to server\n');
    } catch (error) {
      throw new Error(
        `Cannot connect to server at ${SERVER_URL}. Make sure server is running.`
      );
    }

    console.log('Requesting session key from server...');
    let sessionKeyResponse: SessionKeyResponse;

    try {
      sessionKeyResponse = await makeRequest<SessionKeyResponse>('/api/session-key', 'POST');
      if (!sessionKeyResponse.success || !sessionKeyResponse.sessionId) {
        throw new Error('Failed to get session key');
      }
      console.log(`✓ Session created: ${sessionKeyResponse.sessionId.substring(0, 16)}...`);
      console.log(`  Expires in: ${sessionKeyResponse.expiresIn}s\n`);
    } catch (error) {
      throw new Error(`Failed to request session key: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    const privateKeyBuffer = loadPrivateKey();
    const keypair = Keypair.fromSecretKey(privateKeyBuffer);
    const publicKey = keypair.publicKey.toString();

    const voteAccountAddress = await selectValidator();
    const stakingPeriod = await selectStakingPeriod();
    const lamportsToDelegate = getStakingAmount();

    await delegateStake(
      sessionKeyResponse.sessionId,
      privateKeyBuffer,
      publicKey,
      voteAccountAddress,
      lamportsToDelegate,
      stakingPeriod
    );

    privateKeyBuffer.fill(0);
  } catch (error) {
    console.error(`\n✗ Error: ${error instanceof Error ? error.message : 'Unknown error'}\n`);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(`\n✗ Fatal error: ${error.message}\n`);
  process.exit(1);
});
