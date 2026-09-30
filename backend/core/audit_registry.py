"""
Blockchain Audit Registry Service for SMAI Trust Layer Phase 3.

Provides optional on-chain registration of audit integrity hashes using the
AuditRegistry smart contract on EVM-compatible blockchains.
"""
import os
import json
from typing import Optional, Dict, Any, Tuple
from pathlib import Path


class AuditRegistryService:
    """
    Service for interacting with the AuditRegistry smart contract.
    
    Handles registration and verification of audit records on-chain.
    Gracefully handles missing blockchain configuration.
    """
    
    def __init__(self):
        self._configured = False
        self._w3 = None
        self._contract = None
        self._registry_address = None
        self._chain_id = None
        self._private_key = None
        self._auditor_address = None
        
        self._load_configuration()
    
    def _load_configuration(self):
        """
        Load blockchain configuration from environment variables.
        Sets _configured to True only if all required fields are present.
        """
        registry_address = os.getenv("AUDIT_REGISTRY_ADDRESS")
        rpc_url = os.getenv("AUDIT_REGISTRY_RPC_URL")
        private_key = os.getenv("AUDIT_REGISTRY_PRIVATE_KEY")
        chain_id_str = os.getenv("AUDIT_REGISTRY_CHAIN_ID")
        
        # All fields must be present for blockchain functionality
        if not all([registry_address, rpc_url, private_key, chain_id_str]):
            return
        
        try:
            # Import web3.py only if configuration is present
            from web3 import Web3
            from web3.middleware import geth_poa_middleware
            
            self._w3 = Web3(Web3.HTTPProvider(rpc_url))
            
            # Add POA middleware for testnets if needed
            if not self._w3.is_connected():
                return
            
            chain_id = int(chain_id_str)
            self._chain_id = chain_id
            
            # Load contract ABI
            base_dir = Path(__file__).parent.parent.parent
            abi_path = base_dir / "contracts" / "AuditRegistry.abi.json"
            
            if not abi_path.exists():
                return
            
            with open(abi_path, 'r') as f:
                abi = json.load(f)
            
            self._contract = self._w3.eth.contract(
                address=Web3.to_checksum_address(registry_address),
                abi=abi
            )
            
            self._registry_address = registry_address
            self._private_key = private_key
            self._auditor_address = self._w3.eth.account.from_key(private_key).address
            
            self._configured = True
            
        except ImportError:
            # web3.py not installed
            return
        except Exception:
            # Configuration error
            return
    
    def is_configured(self) -> bool:
        """Return True if blockchain service is properly configured."""
        return self._configured
    
    def register_audit(
        self,
        contract_hash: str,
        report_hash: str,
        security_score: int,
        findings_count: int
    ) -> Dict[str, Any]:
        """
        Register an audit on-chain.
        
        Args:
            contract_hash: SHA-256 hash of the audited source (as hex string)
            report_hash: Deterministic canonical hash of the audit report
            security_score: Integer score in [0, 100]
            findings_count: Total number of vulnerability findings
            
        Returns:
            Dict with keys:
            - success: bool
            - audit_id: str (hex) or None
            - tx_hash: str (hex) or None
            - error: str or None
        """
        if not self._configured:
            return {
                "success": False,
                "audit_id": None,
                "tx_hash": None,
                "error": "Blockchain service not configured"
            }
        
        try:
            from web3 import Web3
            
            # Convert hex strings to bytes32
            contract_hash_bytes = Web3.to_bytes(hexstr=contract_hash)
            report_hash_bytes = Web3.to_bytes(hexstr=report_hash)
            
            # Pad to 32 bytes if needed
            contract_hash_bytes = contract_hash_bytes.ljust(32, b'\x00')[:32]
            report_hash_bytes = report_hash_bytes.ljust(32, b'\x00')[:32]
            
            # Build transaction
            nonce = self._w3.eth.get_transaction_count(self._auditor_address)
            
            tx_dict = self._contract.functions.registerAudit(
                contract_hash_bytes,
                report_hash_bytes,
                security_score,
                findings_count
            ).build_transaction({
                'from': self._auditor_address,
                'nonce': nonce,
                'gas': 200000,
                'gasPrice': self._w3.eth.gas_price,
                'chainId': self._chain_id
            })
            
            # Sign transaction
            signed_tx = self._w3.eth.account.sign_transaction(tx_dict, self._private_key)
            
            # Send transaction
            tx_hash = self._w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            # Wait for transaction receipt
            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            if receipt.status == 1:
                # Compute audit ID
                audit_id = self._contract.functions.computeAuditId(
                    contract_hash_bytes,
                    report_hash_bytes,
                    self._auditor_address
                ).call()
                
                return {
                    "success": True,
                    "audit_id": audit_id.hex(),
                    "tx_hash": tx_hash.hex(),
                    "error": None
                }
            else:
                return {
                    "success": False,
                    "audit_id": None,
                    "tx_hash": tx_hash.hex(),
                    "error": "Transaction failed"
                }
                
        except Exception as e:
            return {
                "success": False,
                "audit_id": None,
                "tx_hash": None,
                "error": str(e)
            }
    
    def get_audit(self, audit_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve an audit record from the blockchain.
        
        Args:
            audit_id: Deterministic audit ID (hex string)
            
        Returns:
            Dict with audit record data or None if not found/error
        """
        if not self._configured:
            return None
        
        try:
            from web3 import Web3
            
            audit_id_bytes = Web3.to_bytes(hexstr=audit_id)
            audit_id_bytes = audit_id_bytes.ljust(32, b'\x00')[:32]
            
            record = self._contract.functions.getAudit(audit_id_bytes).call()
            
            if not record[6]:  # exists field
                return None
            
            return {
                "contract_hash": record[0].hex(),
                "report_hash": record[1].hex(),
                "security_score": record[2],
                "findings_count": record[3],
                "timestamp": record[4],
                "auditor": record[5],
                "exists": record[6]
            }
            
        except Exception:
            return None
    
    def verify_audit_integrity(
        self,
        audit_id: str,
        expected_contract_hash: str,
        expected_report_hash: str
    ) -> Dict[str, Any]:
        """
        Verify that on-chain audit data matches local hashes.
        
        Args:
            audit_id: Deterministic audit ID (hex string)
            expected_contract_hash: Expected contract hash (hex string)
            expected_report_hash: Expected report hash (hex string)
            
        Returns:
            Dict with keys:
            - verified: bool
            - on_chain_contract_hash: str or None
            - on_chain_report_hash: str or None
            - error: str or None
        """
        if not self._configured:
            return {
                "verified": False,
                "on_chain_contract_hash": None,
                "on_chain_report_hash": None,
                "error": "Blockchain service not configured"
            }
        
        try:
            record = self.get_audit(audit_id)
            
            if record is None:
                return {
                    "verified": False,
                    "on_chain_contract_hash": None,
                    "on_chain_report_hash": None,
                    "error": "Audit not found on-chain"
                }
            
            # Normalize hashes for comparison
            from web3 import Web3
            
            on_chain_contract = record["contract_hash"].rstrip('0').lower()
            on_chain_report = record["report_hash"].rstrip('0').lower()
            expected_contract = expected_contract_hash.lower()
            expected_report = expected_report_hash.lower()
            
            # Compare
            contract_match = on_chain_contract == expected_contract or \
                           on_chain_contract == expected_contract[:len(on_chain_contract)]
            report_match = on_chain_report == expected_report or \
                         on_chain_report == expected_report[:len(on_chain_report)]
            
            return {
                "verified": contract_match and report_match,
                "on_chain_contract_hash": record["contract_hash"],
                "on_chain_report_hash": record["report_hash"],
                "error": None
            }
            
        except Exception as e:
            return {
                "verified": False,
                "on_chain_contract_hash": None,
                "on_chain_report_hash": None,
                "error": str(e)
            }


# Singleton instance
_audit_registry_service: Optional[AuditRegistryService] = None


def get_audit_registry_service() -> AuditRegistryService:
    """Get the singleton AuditRegistryService instance."""
    global _audit_registry_service
    if _audit_registry_service is None:
        _audit_registry_service = AuditRegistryService()
    return _audit_registry_service
