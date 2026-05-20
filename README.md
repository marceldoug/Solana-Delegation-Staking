# Solana Delegation Staking Client

A command-line interface (CLI) client for delegating and staking SOL on the Solana blockchain. This tool interacts with a custom staking server and the Solana mainnet-beta to securely encrypt your private keys and execute delegation transactions. With this script, you can earn rewards on your staked funds **without having to transfer coins** to anyone.

## Features

* **Validator Selection:** Fetches and displays top active validators on the Solana network to choose from.
* **Flexible Staking Periods:** Pulls available staking periods dynamically from the server.
* **Secure Key Handling:** Accepts private keys via text input or file, and encrypts them locally using AES-256-GCM before sending them to the staking server.
* **Real-time Explorer Links:** Automatically generates Solana Explorer links for tracking your transaction and stake account status upon completion.

## Prerequisites

* **Node.js:** v18.0 or higher (required for native `fetch` API support).
* **Solana Wallet:** A funded Solana wallet with enough SOL to stake and cover minimal transaction fees.

## Installation

Clone the repository and install the required dependencies:

### Install dependencies using npm
If you save the `package.json` file, use
```
npm install
```
If you have only the `client.ts`, use
```
npm install @solana/web3.js bs58 readline-sync typescript ts-node @types/node
```

## Running the script 

Since this is written in TypeScript, use
```
npm start
```
