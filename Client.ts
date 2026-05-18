import { Connection, PublicKey, Keypair, clusterApiUrl } from '@solana/web3.js';
import crypto from 'crypto';
import fs from 'fs';
import readline from 'readline-sync';

// Configuration
const SERVER_URL = 'http://172.31.28.254:3001';
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

interface DelegationResponse {
  success: boolean;
  transactionSignature?: string;
  stakeAccountAddress?: string;
  delegatedTo?: string;
  lamportsDelegated?: number;
  stakingPeriod?: number;
  error?: string;
  details?: string;
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
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return (await response.json()) as T;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Request to ${endpoint} failed: ${errorMsg}`);
  }
}

/**
 * Encrypt private key using AES-256-GCM with provided session key
 */
function encryptPrivateKey(privateKeyBuffer: Buffer, sessionKeyHex: string): {
  encryptedKey: string;
  iv: string;
} {
  try {
    // Generate random 16-byte IV
    const iv = crypto.randomBytes(16);

    // Create cipher with AES-256-GCM
    const sessionKey = Buffer.from(sessionKeyHex, 'hex');
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);

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
 * Load private key from file or stdin
 */
function loadPrivateKey(): Buffer {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║              Load Your Private Key                             ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  const choice = readline.keyInSelect(['Enter as text', 'Load from file'], 'Choose method: ');

  let privateKeyBuffer: Buffer;

  if (choice === 0) {
    // Enter as text
    const privateKeyStr = readline.question('Paste your private key (base58 or raw): ', {
      hideEchoBack: true,
    });

    try {
      // Try to parse as Keypair (which expects base58 format from file or as string)
      const keypair = Keypair.fromSecretKey(Buffer.from(JSON.parse(privateKeyStr)));
      privateKeyBuffer = keypair.secretKey;
    } catch {
      // Try as hex
      try {
        privateKeyBuffer = Buffer.from(privateKeyStr, 'hex');
        if (privateKeyBuffer.length !== 64) {
          throw new Error('Invalid private key length');
        }
      } catch {
        throw new Error('Invalid private key format. Use hex or keypair JSON array');
      }
    }
  } else if (choice === 1) {
    // Load from file
    const filePath = readline.question('Enter path to private key file: ');

    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const fileContent = fs.readFileSync(filePath, 'utf-8');

    try {
      // Try parsing as JSON array (standard Solana format)
      const keypair = Keypair.fromSecretKey(Buffer.from(JSON.parse(fileContent)));
      privateKeyBuffer = keypair.secretKey;
    } catch {
      // Try as hex
      try {
        privateKeyBuffer = Buffer.from(fileContent.trim(), 'hex');
        if (privateKeyBuffer.length !== 64) {
          throw new Error('Invalid private key length');
        }
      } catch {
        throw new Error('Invalid private key format in file');
      }
    }
  } else {
    throw new Error('Invalid choice');
  }

  const keypair = Keypair.fromSecretKey(privateKeyBuffer);
  console.log(`\n✓ Loaded private key for: ${keypair.publicKey.toString()}\n`);

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
    // Get vote accounts from cluster
    // Reference: https://docs.solana.com/consensus/stake-delegation-and-rewards
    const voteAccounts = await connection.getVoteAccounts();

    if (!voteAccounts.current || voteAccounts.current.length === 0) {
      throw new Error('No validators found on cluster');
    }

    // Format validators for display
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

  const solAmount = readline.questionFloat('Enter amount of SOL to stake (e.g., 0.1): ', {
    limitSymbols: true,
  });

  if (solAmount <= 0) {
    throw new Error('Staking amount must be greater than 0');
  }

  // Convert SOL to lamports (1 SOL = 1e9 lamports)
  const lamports = Math.floor(solAmount * 1e9);

  console.log(`\n✓ Staking ${solAmount}◎ (${lamports} lamports)\n`);

  return lamports;
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

    // Step 1: Check server health
    console.log('Checking server connection...');
    try {
      const health = await makeRequest('/api/health', 'GET');
      if (!health.success) {
        throw new Error('Server is not healthy');
      }
      console.log('✓ Connected to server\n');
    } catch (error) {
      throw new Error(
        `Cannot connect to server at ${SERVER_URL}. Make sure server is running: npm run staking:server`
      );
    }

    // Step 2: Request session key from server
    console.log('Requesting session key from server...');
    let sessionKeyResponse: SessionKeyResponse;
    let sessionKey: string;

    try {
      sessionKeyResponse = await makeRequest<SessionKeyResponse>('/api/session-key', 'POST');
      if (!sessionKeyResponse.success || !sessionKeyResponse.sessionId) {
        throw new Error('Failed to get session key');
      }
      console.log(`✓ Session created: ${sessionKeyResponse.sessionId.substring(0, 16)}...`);
      console.log(`  Expires in: ${sessionKeyResponse.expiresIn}s\n`);

      // Derive encryption key from sessionId (server has same key in its store)
      sessionKey = sessionKeyResponse.sessionId;
    } catch (error) {
      throw new Error(`Failed to request session key: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    // Step 3: Load private key
    const privateKeyBuffer = loadPrivateKey();
    const keypair = Keypair.fromSecretKey(privateKeyBuffer);
    const publicKey = keypair.publicKey.toString();

    // Step 4: Select validator
    const voteAccountAddress = await selectValidator();

    // Step 5: Select staking period
    const stakingPeriod = await selectStakingPeriod();

    // Step 6: Get staking amount
    const lamportsToDelegate = getStakingAmount();

    // Step 7: Encrypt private key using session
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║          Encrypting Private Key                               ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');

    console.log('Encrypting private key with AES-256-GCM...');

    // Derive encryption key from sessionId using SHA-256
    const encryptionKey = crypto.createHash('sha256').update(sessionKeyResponse.sessionId).digest('hex');

    let encryptedData: { encryptedKey: string; iv: string };
    try {
      encryptedData = encryptPrivateKey(privateKeyBuffer, encryptionKey);
      console.log('✓ Private key encrypted\n');
    } catch (error) {
      throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    // Step 8: Send delegation request to server
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║          Sending Delegation Request                           ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');

    console.log('Sending encrypted private key and delegation parameters to server...');

    const delegationRequest = {
      sessionId: sessionKeyResponse.sessionId,
      encryptedPrivateKey: encryptedData.encryptedKey,
      iv: encryptedData.iv,
      publicKey,
      voteAccountAddress,
      lamportsToDelegate,
      stakingPeriod,
    };

    let delegationResponse: DelegationResponse;
    try {
      delegationResponse = await makeRequest<DelegationResponse>('/api/delegate-stake', 'POST', delegationRequest);
    } catch (error) {
      throw new Error(`Delegation request failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    if (!delegationResponse.success) {
      throw new Error(`Delegation failed: ${delegationResponse.error} - ${delegationResponse.details}`);
    }

    // Step 9: Display results
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║          Delegation Successful!                               ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');

    console.log(`Transaction Signature: ${delegationResponse.transactionSignature}`);
    console.log(`Stake Account: ${delegationResponse.stakeAccountAddress}`);
    console.log(`Delegated To: ${delegationResponse.delegatedTo}`);
    console.log(`Amount Delegated: ${(delegationResponse.lamportsDelegated! / 1e9).toFixed(9)}◎`);
    console.log(`Staking Period: ${delegationResponse.stakingPeriod} epoch(s)`);
    console.log(`\nStake Status:`);
    console.log(`  State: ${delegationResponse.stakeActivation?.state || 'Unknown'}`);
    console.log(`  Activation Epoch: ${delegationResponse.stakeActivation?.activationEpoch || 'Pending'}`);

    console.log(`\n→ View on explorer: https://explorer.solana.com/tx/${delegationResponse.transactionSignature}?cluster=mainnet-beta`);
    console.log(
      `→ View stake account: https://explorer.solana.com/account/${delegationResponse.stakeAccountAddress}?cluster=mainnet-beta\n`
    );

    // Cleanup
    privateKeyBuffer.fill(0);
  } catch (error) {
    console.error(`\n✗ Error: ${error instanceof Error ? error.message : 'Unknown error'}\n`);
    process.exit(1);
  }
}

// Run main
main();