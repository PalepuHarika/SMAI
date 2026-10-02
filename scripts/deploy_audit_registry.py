#!/usr/bin/env python3
"""
Sepolia Deployment Script for AuditRegistry Contract

Deploys the AuditRegistry.sol smart contract to the Sepolia testnet using web3.py.
Reads configuration from environment variables only.

Environment Variables Required:
    SEPOLIA_RPC_URL: Sepolia RPC endpoint URL
    DEPLOYER_PRIVATE_KEY: Private key of the deployer account (with Sepolia ETH)

Usage:
    export SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/YOUR_PROJECT_ID"
    export DEPLOYER_PRIVATE_KEY="your_private_key_here"
    python scripts/deploy_audit_registry.py
"""
import os
import sys
import json
from pathlib import Path

# Check for web3.py
try:
    from web3 import Web3
    from web3.exceptions import TransactionNotFound, ContractLogicError
except ImportError:
    print("ERROR: web3.py is not installed.")
    print("Install it with: pip install web3")
    sys.exit(1)


# Configuration
SEPOLIA_CHAIN_ID = 11155111
CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
ABI_FILE = CONTRACTS_DIR / "AuditRegistry.abi.json"
BIN_FILE = CONTRACTS_DIR / "AuditRegistry.bin"


def load_contract_artifacts():
    """Load ABI and bytecode from files."""
    if not ABI_FILE.exists():
        raise FileNotFoundError(f"ABI file not found: {ABI_FILE}")
    if not BIN_FILE.exists():
        raise FileNotFoundError(f"Bytecode file not found: {BIN_FILE}")
    
    with open(ABI_FILE, 'r') as f:
        abi = json.load(f)
    
    with open(BIN_FILE, 'r') as f:
        bytecode = f.read().strip()
    
    # Remove '0x' prefix if present
    if bytecode.startswith('0x'):
        bytecode = bytecode[2:]
    
    return abi, bytecode


def get_environment_variables():
    """Load and validate environment variables."""
    rpc_url = os.environ.get("SEPOLIA_RPC_URL")
    private_key = os.environ.get("DEPLOYER_PRIVATE_KEY")
    
    if not rpc_url:
        raise ValueError("SEPOLIA_RPC_URL environment variable is not set")
    if not private_key:
        raise ValueError("DEPLOYER_PRIVATE_KEY environment variable is not set")
    
    # Validate private key format
    if not private_key.startswith('0x'):
        private_key = '0x' + private_key
    
    if len(private_key) != 66:
        raise ValueError("Invalid private key format (must be 32 bytes / 64 hex chars)")
    
    return rpc_url, private_key


def verify_chain_id(w3: Web3):
    """Verify the connected network is Sepolia."""
    chain_id = w3.eth.chain_id
    if chain_id != SEPOLIA_CHAIN_ID:
        raise ValueError(
            f"Wrong network! Expected Sepolia (chain ID {SEPOLIA_CHAIN_ID}), "
            f"but connected to chain ID {chain_id}"
        )
    return chain_id


def deploy_contract():
    """Deploy the AuditRegistry contract to Sepolia."""
    print("=" * 60)
    print("AuditRegistry Sepolia Deployment")
    print("=" * 60)
    
    # Load artifacts
    print("\n[1/6] Loading contract artifacts...")
    abi, bytecode = load_contract_artifacts()
    print(f"      ABI loaded from: {ABI_FILE}")
    print(f"      Bytecode loaded from: {BIN_FILE}")
    
    # Load environment variables
    print("\n[2/6] Loading environment variables...")
    rpc_url, private_key = get_environment_variables()
    print(f"      RPC URL: {rpc_url[:30]}..." if len(rpc_url) > 30 else f"      RPC URL: {rpc_url}")
    print(f"      Private key: loaded (hidden)")
    
    # Connect to RPC
    print("\n[3/6] Connecting to Sepolia RPC...")
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")
    print(f"      Connected successfully")
    
    # Verify chain ID
    print("\n[4/6] Verifying network chain ID...")
    chain_id = verify_chain_id(w3)
    print(f"      Chain ID: {chain_id} (Sepolia)")
    
    # Get deployer account
    print("\n[5/6] Preparing deployer account...")
    account = w3.eth.account.from_key(private_key)
    deployer_address = account.address
    print(f"      Deployer address: {deployer_address}")
    
    # Check balance
    balance = w3.eth.get_balance(deployer_address)
    balance_eth = w3.from_wei(balance, 'ether')
    print(f"      Balance: {balance_eth:.6f} ETH")
    
    if balance_eth < 0.01:
        print(f"      WARNING: Low balance. Deployment may fail.")
    
    # Build deployment transaction
    print("\n[6/6] Deploying contract...")
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    # Get latest block for gas estimation
    latest_block = w3.eth.get_block('latest')
    base_fee = latest_block['baseFeePerGas']
    
    # Set gas price (slightly above base fee for faster inclusion)
    max_priority_fee = w3.to_wei(1, 'gwei')
    max_fee_per_gas = base_fee + max_priority_fee
    
    # Estimate gas
    try:
        gas_estimate = contract.constructor().estimate_gas({'from': deployer_address})
        gas_limit = int(gas_estimate * 1.2)  # 20% buffer
    except Exception as e:
        print(f"      Gas estimation failed: {e}")
        gas_limit = 500000  # Fallback
    
    print(f"      Gas limit: {gas_limit}")
    
    # Build transaction
    tx_dict = contract.constructor().build_transaction({
        'from': deployer_address,
        'gas': gas_limit,
        'maxFeePerGas': max_fee_per_gas,
        'maxPriorityFeePerGas': max_priority_fee,
        'nonce': w3.eth.get_transaction_count(deployer_address),
        'chainId': chain_id,
    })
    
    # Sign transaction
    signed_tx = w3.eth.account.sign_transaction(tx_dict, private_key)
    tx_hash = signed_tx.hash.hex()
    print(f"      Transaction hash: {tx_hash}")
    
    # Send transaction
    print("\n      Sending transaction...")
    tx_sent = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"      Transaction sent")
    
    # Wait for receipt
    print("\n      Waiting for confirmation...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    
    if receipt['status'] == 1:
        print(f"      ✓ Transaction confirmed")
    else:
        raise RuntimeError("Transaction failed (reverted)")
    
    # Extract deployment info
    contract_address = receipt['contractAddress']
    block_number = receipt['blockNumber']
    
    # Verify bytecode at address
    print("\n[Verification] Checking deployed bytecode...")
    deployed_code = w3.eth.get_code(contract_address)
    if len(deployed_code) > 0:
        print(f"      ✓ Bytecode verified at contract address")
    else:
        raise RuntimeError("No bytecode found at contract address")
    
    # Print deployment summary
    print("\n" + "=" * 60)
    print("DEPLOYMENT SUCCESSFUL")
    print("=" * 60)
    print(f"Deployer address:  {deployer_address}")
    print(f"Chain ID:          {chain_id}")
    print(f"Contract address:  {contract_address}")
    print(f"Transaction hash:  {tx_hash}")
    print(f"Block number:      {block_number}")
    print(f"Gas used:          {receipt['gasUsed']}")
    print("=" * 60)
    
    # Print environment variable configuration for backend
    print("\nBackend Configuration:")
    print(f"export AUDIT_REGISTRY_ADDRESS={contract_address}")
    print(f"export AUDIT_REGISTRY_RPC_URL={rpc_url}")
    print(f"export AUDIT_REGISTRY_CHAIN_ID={chain_id}")
    print(f"# DEPLOYER_PRIVATE_KEY should be set separately for backend operations")
    print("=" * 60)


def main():
    """Main entry point."""
    try:
        deploy_contract()
        sys.exit(0)
    except FileNotFoundError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
    except ConnectionError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Deployment failed - {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
