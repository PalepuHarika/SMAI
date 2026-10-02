# AuditRegistry Sepolia Deployment Guide

This guide explains how to safely deploy the AuditRegistry smart contract to the Sepolia Ethereum testnet.

## Prerequisites

1. **Install web3.py** (if not already installed):
   ```bash
   pip install web3
   ```

2. **Obtain Sepolia testnet ETH**:
   - Use a faucet like https://sepoliafaucet.com or https://faucet.quicknode.com/ethereum/sepolia
   - You need at least 0.01 ETH for deployment

3. **Get a Sepolia RPC URL**:
   - Free options: Alchemy, Infura, QuickNode, or public nodes
   - Example: `https://sepolia.infura.io/v3/YOUR_PROJECT_ID`

## Deployment Steps

### 1. Set Environment Variables

Set the required environment variables in your terminal:

**Linux/macOS:**
```bash
export SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/YOUR_PROJECT_ID"
export DEPLOYER_PRIVATE_KEY="your_private_key_here"
```

**Windows (PowerShell):**
```powershell
$env:SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/YOUR_PROJECT_ID"
$env:DEPLOYER_PRIVATE_KEY="your_private_key_here"
```

**Windows (Command Prompt):**
```cmd
set SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_PROJECT_ID
set DEPLOYER_PRIVATE_KEY=your_private_key_here
```

### 2. Run the Deployment Script

```bash
python scripts/deploy_audit_registry.py
```

### 3. Verify Deployment

The script will:
- Verify the network is Sepolia (chain ID 11155111)
- Check your account balance
- Deploy the contract
- Wait for transaction confirmation
- Verify bytecode at the deployed address
- Print deployment details

## Expected Output

On success, you will see:
```
============================================================
DEPLOYMENT SUCCESSFUL
============================================================
Deployer address:  0x...
Chain ID:          11155111
Contract address:  0x...
Transaction hash:  0x...
Block number:      ...
Gas used:          ...
============================================================
```

## Post-Deployment Configuration

After successful deployment, configure your backend with these environment variables:

```bash
export AUDIT_REGISTRY_ADDRESS=0x...  # Contract address from deployment
export AUDIT_REGISTRY_RPC_URL=https://sepolia.infura.io/v3/YOUR_PROJECT_ID
export AUDIT_REGISTRY_CHAIN_ID=11155111
export AUDIT_REGISTRY_PRIVATE_KEY=your_private_key_here  # For backend transactions
```

## Security Notes

- **NEVER commit private keys** to version control
- **NEVER share private keys** in chat or public channels
- Use a dedicated testnet account (not your mainnet wallet)
- The private key is only used in memory and never printed or logged
- The script validates the chain ID before deploying to prevent accidental mainnet deployment

## Troubleshooting

### "web3.py is not installed"
```bash
pip install web3
```

### "SEPOLIA_RPC_URL environment variable is not set"
Ensure you set both environment variables before running the script.

### "Wrong network! Expected Sepolia"
Check your RPC URL points to Sepolia, not mainnet or another testnet.

### "Low balance. Deployment may fail"
Get more Sepolia ETH from a faucet before deploying.

### "Transaction failed (reverted)"
Check the contract bytecode file exists and is valid. Ensure you have sufficient gas.

## Contract Verification

After deployment, you can verify the contract on Etherscan Sepolia:
1. Go to https://sepolia.etherscan.io/
2. Search for your contract address
3. Use the "Verify and Publish" feature with:
   - Compiler: Solidity
   - Version: 0.8.20
   - License: MIT
   - Contract source: `contracts/AuditRegistry.sol`
