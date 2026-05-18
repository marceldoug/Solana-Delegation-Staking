import express, { Request, Response } from 'express';
import { Connection, PublicKey, Keypair, StakeProgram, sendAndConfirmTransaction, Transaction } from '@solana/web3.js';
import crypto from 'crypto';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.SERVER_PORT || 3000;

// Solana Configuration
/* ************************************************************************
 * **** [REDACTED] INFRASTRUCTURE PROVIDER ********************************
 * **** Default RPC URL removed to protect infrastructure endpoints.     ****
 * ************************************************************************
 */
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const connection = new Connection(SOLANA_RPC_URL, 'confirmed');

// Session Management
interface Session {
  key: Buffer;
  createdAt: number;
  expiresAt: number;
}

const sessions = new Map<string, Session>();
const SESSION_TIMEOUT = parseInt(process.env.SESSION_TIMEOUT || '600', 10) * 1000; // Convert to ms

// Cleanup expired sessions every minute
setInterval(() => {
  const now = Date.now();
  for (const [sessionId, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(sessionId);
      console.log(`[v0] Session ${sessionId} expired and removed`);
    }
  }
}, 60000);

// Middleware
app.use(express.json());

// ============================================================================
// ROUTES
// ============================================================================

/**
 * GET /api/staking-periods
 * Returns available staking periods based on Solana staking rules
 */
app.get('/api/staking-periods', (req: Request, res: Response) => {
  try {
    const stakingPeriods = [
      { label: 'Minimum (1 epoch)', value: 1, description: 'Rewards apply after 1 epoch (~2-3 days)' },
      { label: 'Short-term (2 epochs)', value: 2, description: 'Rewards apply after 2 epochs (~4-6 days)' },
      { label: 'Medium-term (5 epochs)', value: 5, description: 'Rewards apply after 5 epochs (~10-15 days)' },
      { label: 'Long-term (10 epochs)', value: 10, description: 'Rewards apply after 10 epochs (~20-30 days)' },
    ];

    res.json({
      success: true,
      periods: stakingPeriods,
      note: 'Staking rewards are credited at epoch boundaries.',
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch staking periods' });
  }
});

/**
 * POST /api/session-key
 * Generates a unique session key for encryption
 */
app.post('/api/session-key', (req: Request, res: Response) => {
  try {
    const encryptionKey = crypto.randomBytes(32);
    const sessionId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    
    sessions.set(sessionId, { key: encryptionKey, createdAt: now, expiresAt: now + SESSION_TIMEOUT });

    res.json({ success: true, sessionId, expiresIn: SESSION_TIMEOUT / 1000 });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to generate session key' });
  }
});

/**
 * POST /api/delegate-stake
 * Receives encrypted private key and delegation parameters
 * Decrypts, signs, and sends delegation transaction
 */
app.post('/api/delegate-stake', async (req: Request, res: Response) => {
  try {
    const {
      sessionId,
      encryptedPrivateKey,
      iv,
      publicKey: publicKeyStr,
      voteAccountAddress: voteAccountAddressStr,
      lamportsToDelegate,
      stakingPeriod,
    } = req.body;

    if (!sessionId || !encryptedPrivateKey || !iv || !publicKeyStr || !voteAccountAddressStr || !lamportsToDelegate) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    // Step 1: Retrieve session key
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Invalid or expired session' });
    }

    // Step 2 & 3: Decrypt private key and reconstruct Keypair
    /* ************************************************************************
     * **** [REDACTED] CRYPTOGRAPHIC BOUNDARY *********************************
     * **** AES-256-GCM Decryption and Keypair hydration omitted.          ****
     * ************************************************************************
     */
    let decryptedPrivateKey = Buffer.alloc(64); // **** MOCKED FOR COMPILATION ****
    let userKeypair = Keypair.generate();       // **** MOCKED FOR COMPILATION ****

    // Safety check to ensure this redacted file isn't executed as-is
    if (true) {
        throw new Error("**** CRITICAL DECRYPTION AND KEY HYDRATION LOGIC REMOVED ****");
    }

    // Step 4: Parse and validate public keys
    let voteAccountAddress = new PublicKey(voteAccountAddressStr);
    let userPublicKey = new PublicKey(publicKeyStr);

    // Step 5: Create stake account if needed
    const stakeAccountKeypair = Keypair.generate();
    const minimumLamportsForStakeAccount = await connection.getMinimumBalanceForRentExemption(200); 

    const lamportsToStake = Math.max(lamportsToDelegate, minimumLamportsForStakeAccount + 1);

    // Step 6: Build transaction with proper instructions
    const transaction = new Transaction();

    // Create stake account
    const createStakeAccountIx = StakeProgram.createAccount({
      fromPubkey: userPublicKey,
      stakePubkey: stakeAccountKeypair.publicKey,
      authorized: {
        staker: userPublicKey,
        withdrawer: userPublicKey,
      },
      lamports: lamportsToStake,
    });
    transaction.add(createStakeAccountIx);

    // Delegate stake to validator
    const delegateStakeIx = StakeProgram.delegate({
      stakePubkey: stakeAccountKeypair.publicKey,
      authorizedPubkey: userPublicKey,
      votePubkey: voteAccountAddress,
    });
    transaction.add(delegateStakeIx);

    // Step 7: Get latest blockhash
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
    transaction.recentBlockhash = blockhash;
    transaction.feePayer = userPublicKey;

    // Step 8: Sign transaction
    transaction.sign(userKeypair, stakeAccountKeypair);

    // Step 9: Send transaction
    const txSignature = await connection.sendTransaction(transaction, [userKeypair, stakeAccountKeypair], {
      preflightCommitment: 'confirmed',
    });

    // Step 10: Confirm transaction
    const confirmation = await connection.confirmTransaction(
      { signature: txSignature, blockhash, lastValidBlockHeight },
      'confirmed'
    );

    if (confirmation.value.err) {
      throw new Error('Transaction failed');
    }

    // Step 11: Get stake account info for verification
    const stakeActivation = await connection.getStakeActivation(stakeAccountKeypair.publicKey);

    // Step 12: Immediately destroy session key
    sessions.delete(sessionId);

    // Clear sensitive data from memory
    decryptedPrivateKey.fill(0);
    userKeypair = null as any;

    res.json({
      success: true,
      transactionSignature: txSignature,
      stakeAccountAddress: stakeAccountKeypair.publicKey.toString(),
      delegatedTo: voteAccountAddressStr,
      lamportsDelegated: lamportsToStake,
      stakingPeriod: stakingPeriod || 1,
      stakeActivation: {
        state: stakeActivation.state,
        activationEpoch: stakeActivation.activationEpoch,
        deactivationEpoch: stakeActivation.deactivationEpoch,
      },
    });
  } catch (error) {
    // Ensure session is destroyed on error
    if (req.body?.sessionId) sessions.delete(req.body.sessionId);
    res.status(500).json({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
  }
});

/**
 * Health check endpoint
 */
app.get('/api/health', (req: Request, res: Response) => {
  res.json({ success: true, status: 'Server is running', activeSessionCount: sessions.size });
});

app.listen(PORT, () => {
  console.log(`✓ Solana Delegation Server running on http://localhost:${PORT}`);
});
