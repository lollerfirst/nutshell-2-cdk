#!/usr/bin/env python3
"""
Nutshell to CDK Database Migration Script

This script migrates data from a Nutshell SQLite database to a CDK SQLite database.
It handles complex logic for schema transformations, data validation, and provides
detailed migration statistics and verification queries.

Usage: python3 nutshell_to_cdk_migration.py <nutshell_db_path> <cdk_db_path>
"""

import sqlite3
import sys
import os
import re
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import logging
import binascii

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NutshellToCDKMigrator:
    """Handles migration from Nutshell database to CDK database format."""
    
    def __init__(self, nutshell_db_path: str, cdk_db_path: str):
        self.nutshell_db_path = Path(nutshell_db_path)
        self.cdk_db_path = Path(cdk_db_path)
        self.nutshell_conn: Optional[sqlite3.Connection] = None
        self.cdk_conn: Optional[sqlite3.Connection] = None
        
    def validate_inputs(self) -> None:
        """Validate that input database files exist."""
        if not self.nutshell_db_path.exists():
            raise FileNotFoundError(f"Nutshell database file '{self.nutshell_db_path}' does not exist")
        
        if not self.cdk_db_path.exists():
            raise FileNotFoundError(f"CDK database file '{self.cdk_db_path}' does not exist")
    
    def connect_databases(self) -> None:
        """Establish connections to both databases."""
        try:
            self.nutshell_conn = sqlite3.connect(str(self.nutshell_db_path))
            self.nutshell_conn.row_factory = sqlite3.Row  # Access columns by name
            
            self.cdk_conn = sqlite3.connect(str(self.cdk_db_path))
            self.cdk_conn.row_factory = sqlite3.Row
            
            logger.info("Database connections established successfully")
        except sqlite3.Error as e:
            raise RuntimeError(f"Failed to connect to databases: {e}")
    
    def close_connections(self) -> None:
        """Close database connections."""
        if self.nutshell_conn:
            self.nutshell_conn.close()
        if self.cdk_conn:
            self.cdk_conn.close()
    
    def hex_to_blob(self, hex_string: Optional[str]) -> Optional[bytes]:
        """
        Convert hex string to bytes for BLOB fields.
        
        Args:
            hex_string: Hex string from Nutshell database
            
        Returns:
            Bytes object for CDK BLOB field, or None if input is None/empty
        """
        if not hex_string:
            return None
        
        try:
            # Remove any '0x' prefix if present
            clean_hex = hex_string.replace('0x', '')
            return bytes.fromhex(clean_hex)
        except ValueError as e:
            logger.warning(f"Failed to convert hex string '{hex_string}' to bytes: {e}")
            return None
    
    def parse_version(self, version: str) -> Tuple[int, int, int]:
        """Parse semantic version string into tuple of integers."""
        if not version:
            return (0, 0, 0)
        
        # Remove any prefix (like 'v') and split by dots
        clean_version = re.sub(r'^v?', '', version)
        parts = clean_version.split('.')
        
        try:
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            return (major, minor, patch)
        except ValueError:
            logger.warning(f"Invalid version format: {version}, treating as 0.0.0")
            return (0, 0, 0)
    
    def is_version_gte_015(self, version: str) -> bool:
        """Check if version is >= 0.15.0."""
        major, minor, patch = self.parse_version(version)
        return major > 0 or (major == 0 and minor >= 15)
    
    def parse_derivation_path(self, derivation_path: str) -> Tuple[str, int]:
        """
        Parse derivation path into base path and index.
        
        Args:
            derivation_path: Full derivation path like "m/0'/1'/2'/3"
            
        Returns:
            Tuple of (base_path, index) where base_path is the full path
            and index is the last component as integer
        """
        if not derivation_path or derivation_path == '':
            return ('0', 0)
        
        # Remove 'm/' prefix if present
        path = derivation_path
        if path.startswith('m/'):
            path = path[2:]
        
        # Split by '/' and get components
        components = path.split('/')
        if len(components) == 0:
            return ('0', 0)
        
        # For CDK, we use the full path as base_path
        # and extract the index from the last component
        base_path = path
        last_component = components[-1]
        
        try:
            index = int(last_component.replace("'", ""))
        except ValueError:
            index = 0
        
        return (base_path, index)
    
    def calculate_max_order(self, amounts_json: str) -> int:
        """
        Calculate max_order based on amounts.
        """
        if not amounts_json or amounts_json in ['[]', 'null']:
            return 0
        
        amounts = json.loads(amounts_json)

        return len(amounts)
    
    def warn_incompatible_keysets(self) -> int:
        """Warn about Nutshell keysets incompatible with CDK before migration.
        
        A keyset is considered compatible if its version is >= 0.15.0.
        Prints a warning including the keyset id for each incompatible keyset.
        
        Returns:
            int: Number of incompatible keysets found.
        """
        if not self.nutshell_conn:
            raise RuntimeError("Nutshell database is not connected")
        
        cur = self.nutshell_conn.cursor()
        try:
            cur.execute("SELECT id, version FROM keysets")
        except sqlite3.Error as e:
            logger.error(f"Unable to read keysets for compatibility check: {e}")
            return 0
        
        incompatible = 0
        for row in cur.fetchall():
            keyset_id = row["id"]
            version = row["version"]
            if version is None or not self.is_version_gte_015(version):
                incompatible += 1
                # Exact-style warning message with keyset id included
                print(f"WARNING: this keyset is incompatible with CDK and therefore won't be migrated! (id={keyset_id})")
        
        if incompatible:
            logger.info(f"Found {incompatible} incompatible keyset(s) that will be skipped during migration")
        else:
            logger.info("All keysets appear compatible (>= 0.15.0)")
        return incompatible

    def migrate_keysets(self) -> int:
        """Migrate keysets from Nutshell to CDK format."""
        logger.info("Migrating keysets...")
        
        # Query Nutshell keysets with version >= 0.16
        nutshell_cursor = self.nutshell_conn.cursor()
        nutshell_cursor.execute("""
            SELECT id, unit, active, valid_from, valid_to, derivation_path, 
                   amounts, input_fee_ppk, version
            FROM keysets 
            WHERE version IS NOT NULL
        """
        )
        
        migrated_count = 0
        cdk_cursor = self.cdk_conn.cursor()
        
        for row in nutshell_cursor.fetchall():
            # Check version requirement
            if not self.is_version_gte_015(row['version']):
                logger.debug(f"Skipping keyset {row['id']} with version {row['version']} < 0.16")
                continue
            
            # Parse derivation path
            base_path, path_index = self.parse_derivation_path(row['derivation_path'])
            
            # Prepare CDK keyset data
            keyset_data = {
                'id': row['id'],
                'unit': row['unit'] or 'sat',
                'active': bool(row['active']) if row['active'] is not None else True,
                'valid_from': row['valid_from'],
                'valid_to': row['valid_to'] if row['valid_to'] else None,
                'derivation_path': base_path,
                'max_order': self.calculate_max_order(row['amounts']),
                'input_fee_ppk': row['input_fee_ppk'] or 0,
                'derivation_path_index': path_index
            }
            
            # Insert into CDK database
            try:
                cdk_cursor.execute("""
                    INSERT OR IGNORE INTO keyset (
                        id, unit, active, valid_from, valid_to, derivation_path,
                        max_order, input_fee_ppk, derivation_path_index
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    keyset_data['id'], keyset_data['unit'], keyset_data['active'],
                    keyset_data['valid_from'], keyset_data['valid_to'],
                    keyset_data['derivation_path'], keyset_data['max_order'],
                    keyset_data['input_fee_ppk'], keyset_data['derivation_path_index']
                ))
                
                if cdk_cursor.rowcount > 0:
                    migrated_count += 1
                    logger.debug(f"Migrated keyset: {row['id']}")
                
            except sqlite3.Error as e:
                logger.error(f"Failed to migrate keyset {row['id']}: {e}")
        
        self.cdk_conn.commit()
        logger.info(f"Migrated {migrated_count} keysets")
        return migrated_count
    
    def migrate_proofs_used(self) -> int:
        """Migrate spent proofs from Nutshell to CDK format."""
        logger.info("Migrating spent proofs...")
        
        nutshell_cursor = self.nutshell_conn.cursor()
        nutshell_cursor.execute("""
            SELECT pu.y, pu.amount, pu.id as keyset_id, pu.secret, pu.c, 
                   pu.witness, pu.created
            FROM proofs_used pu
            JOIN keysets k ON k.id = pu.id
            WHERE k.version IS NOT NULL
        """)
        
        migrated_count = 0
        cdk_cursor = self.cdk_conn.cursor()
        
        for row in nutshell_cursor.fetchall():
            # Check if keyset version is >= 0.16
            keyset_cursor = self.nutshell_conn.cursor()
            keyset_cursor.execute("SELECT version FROM keysets WHERE id = ?", (row['keyset_id'],))
            keyset_row = keyset_cursor.fetchone()
            
            # Convert hex strings to blobs for CDK

            if not keyset_row or not self.is_version_gte_015(keyset_row['version']):
                continue
            
            # Convert hex strings to blobs for CDK
            y_blob = self.hex_to_blob(row['y'])
            c_blob = self.hex_to_blob(row['c'])
            
            if not y_blob:
                logger.warning(f"Skipping proof with invalid hex data: y={row['y']}, c={row['c']}")
                continue
            
            if not c_blob:
                logger.warning(f"No blind signature found for spent proof with: y={row['y']}. Setting to a default valid public key.")
                c_blob = self.hex_to_blob("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798") # G
            
            proof_data = {
                'y': y_blob,
                'amount': row['amount'],
                'keyset_id': row['keyset_id'],
                'secret': row['secret'],
                'c': c_blob,
                'witness': row['witness'],
                'state': 'SPENT',
                'quote_id': None,
                'created_time': row['created']
            }
            
            try:
                cdk_cursor.execute("""
                    INSERT OR IGNORE INTO proof (
                        y, amount, keyset_id, secret, c, witness, state, quote_id, created_time
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    proof_data['y'], proof_data['amount'], proof_data['keyset_id'],
                    proof_data['secret'], proof_data['c'], proof_data['witness'],
                    proof_data['state'], proof_data['quote_id'], proof_data['created_time']
                ))
                
                if cdk_cursor.rowcount > 0:
                    migrated_count += 1
                
            except sqlite3.Error as e:
                logger.error(f"Failed to migrate spent proof: {e}")
        
        self.cdk_conn.commit()
        logger.info(f"Migrated {migrated_count} spent proofs")
        return migrated_count
    
    def migrate_proofs_pending(self) -> int:
        """Migrate pending proofs from Nutshell to CDK format."""
        logger.info("Migrating pending proofs...")
        
        nutshell_cursor = self.nutshell_conn.cursor()
        nutshell_cursor.execute("""
            SELECT pp.y, pp.amount, pp.id as keyset_id, pp.secret, pp.c, pp.created
            FROM proofs_pending pp
            JOIN keysets k ON k.id = pp.id
            WHERE k.version IS NOT NULL
        """)
        
        migrated_count = 0
        cdk_cursor = self.cdk_conn.cursor()
        
        for row in nutshell_cursor.fetchall():
            # Check if keyset version is >= 0.16
            keyset_cursor = self.nutshell_conn.cursor()
            keyset_cursor.execute("SELECT version FROM keysets WHERE id = ?", (row['keyset_id'],))
            keyset_row = keyset_cursor.fetchone()
            
            if not keyset_row or not self.is_version_gte_015(keyset_row['version']):
                continue
            
            # Generate random y if not available, then convert to blob
            y_hex = row['y']
            if not y_hex:
                import secrets
                y_hex = secrets.token_hex(32)
            
            y_blob = self.hex_to_blob(y_hex)
            c_blob = self.hex_to_blob(row['c'])
            
            if not y_blob or not c_blob:
                logger.warning(f"Skipping proof with invalid hex data: y={y_hex}, c={row['c']}")
                continue
            
            proof_data = {
                'y': y_blob,
                'amount': row['amount'],
                'keyset_id': row['keyset_id'],
                'secret': row['secret'],
                'c': c_blob,
                'witness': None,  # Pending proofs typically don't have witness
                'state': 'PENDING',
                'quote_id': None,
                'created_time': row['created']
            }
            
            try:
                cdk_cursor.execute("""
                    INSERT OR IGNORE INTO proof (
                        y, amount, keyset_id, secret, c, witness, state, quote_id, created_time
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    proof_data['y'], proof_data['amount'], proof_data['keyset_id'],
                    proof_data['secret'], proof_data['c'], proof_data['witness'],
                    proof_data['state'], proof_data['quote_id'], proof_data['created_time']
                ))
                
                if cdk_cursor.rowcount > 0:
                    migrated_count += 1
                
            except sqlite3.Error as e:
                logger.error(f"Failed to migrate pending proof: {e}")
        
        self.cdk_conn.commit()
        logger.info(f"Migrated {migrated_count} pending proofs")
        return migrated_count
    
    def migrate_promises(self) -> int:
        """Migrate promises (blind signatures) from Nutshell to CDK format."""
        logger.info("Migrating promises (blind signatures)...")
        
        nutshell_cursor = self.nutshell_conn.cursor()
        nutshell_cursor.execute("""
            SELECT p.b_, p.amount, p.id as keyset_id, p.c_, p.dleq_e, p.dleq_s, p.created
            FROM promises p
            JOIN keysets k ON k.id = p.id
            WHERE k.version IS NOT NULL
        """)
        
        migrated_count = 0
        cdk_cursor = self.cdk_conn.cursor()
        
        for row in nutshell_cursor.fetchall():
            # Check if keyset version is >= 0.16
            keyset_cursor = self.nutshell_conn.cursor()
            keyset_cursor.execute("SELECT version FROM keysets WHERE id = ?", (row['keyset_id'],))
            keyset_row = keyset_cursor.fetchone()
            
            if not keyset_row or not self.is_version_gte_015(keyset_row['version']):
                continue
            
            # Convert hex strings to blobs for CDK
            blinded_message_blob = self.hex_to_blob(row['b_'])
            c_blob = self.hex_to_blob(row['c_'])
            
            if not blinded_message_blob or not c_blob:
                logger.warning(f"Skipping promise with invalid hex data: b_={row['b_']}, c_={row['c_']}")
                continue
            
            signature_data = {
                'blinded_message': blinded_message_blob,
                'amount': row['amount'],
                'keyset_id': row['keyset_id'],
                'c': c_blob,
                'dleq_e': row['dleq_e'],
                'dleq_s': row['dleq_s'],
                'quote_id': None,
                'created_time': row['created']
            }
            
            try:
                cdk_cursor.execute("""
                    INSERT OR IGNORE INTO blind_signature (
                        blinded_message, amount, keyset_id, c, dleq_e, dleq_s, quote_id, created_time
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    signature_data['blinded_message'], signature_data['amount'],
                    signature_data['keyset_id'], signature_data['c'],
                    signature_data['dleq_e'], signature_data['dleq_s'],
                    signature_data['quote_id'], signature_data['created_time']
                ))
                
                if cdk_cursor.rowcount > 0:
                    migrated_count += 1
                
            except sqlite3.Error as e:
                logger.error(f"Failed to migrate promise: {e}")
        
        self.cdk_conn.commit()
        logger.info(f"Migrated {migrated_count} promises (blind signatures)")
        return migrated_count
    
    def migrate_mint_quotes(self) -> int:
        """Migrate mint quotes from Nutshell to CDK format."""
        logger.info("Migrating mint quotes...")
        
        nutshell_cursor = self.nutshell_conn.cursor()
        nutshell_cursor.execute("""
            SELECT quote, amount, unit, request, checking_id, pubkey, created_time,
                   state, method
            FROM mint_quotes
        """)
        
        migrated_count = 0
        cdk_cursor = self.cdk_conn.cursor()
        
        for row in nutshell_cursor.fetchall():
            created_time = int(row['created_time'])
            expiry_time = created_time + 157784760  # + 5 years from creation
            
            # Map Nutshell state to CDK amounts
            amount_paid = row['amount'] if row['state'] in ['PAID', 'ISSUED'] else 0
            amount_issued = row['amount'] if row['state'] == 'ISSUED' else 0
            
            quote_data = {
                'id': row['quote'],
                'amount': row['amount'],
                'unit': row['unit'] or 'sat',
                'request': row['request'],
                'expiry': expiry_time,
                'request_lookup_id': row['checking_id'],
                'pubkey': row['pubkey'] if row['pubkey'] != "" else None,
                'created_time': created_time,
                'amount_paid': amount_paid,
                'amount_issued': amount_issued,
                'payment_method': (row['method'] or 'BOLT11').upper(),
                'request_lookup_id_kind': 'payment_hash'
            }
            
            try:
                cdk_cursor.execute("""
                    INSERT OR IGNORE INTO mint_quote (
                        id, amount, unit, request, expiry, request_lookup_id, pubkey,
                        created_time, amount_paid, amount_issued, payment_method,
                        request_lookup_id_kind
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    quote_data['id'], quote_data['amount'], quote_data['unit'],
                    quote_data['request'], quote_data['expiry'], quote_data['request_lookup_id'],
                    quote_data['pubkey'], quote_data['created_time'], quote_data['amount_paid'],
                    quote_data['amount_issued'], quote_data['payment_method'],
                    quote_data['request_lookup_id_kind']
                ))
                
                if cdk_cursor.rowcount > 0:
                    migrated_count += 1
                
            except sqlite3.Error as e:
                logger.error(f"Failed to migrate mint quote {row['quote']}: {e}")
        
        self.cdk_conn.commit()
        logger.info(f"Migrated {migrated_count} mint quotes")
        return migrated_count
    
    

    def _select_melt_quotes_to_migrate(self) -> Tuple[List[sqlite3.Row], List[Dict[str, Any]]]:
        """
        Select melt quotes to migrate, deduplicating by checking_id (payment lookup id).
        Rules per checking_id group:
        - If any quote is PAID, pick the PAID one with the latest paid_time (fallback created_time).
        - Otherwise (all unpaid/pending), pick the latest by created_time.
        - Quotes with NULL/empty checking_id are treated as unique (no grouping).

        Returns:
            (selected_rows, duplicates_info)
            - selected_rows: rows to migrate
            - duplicates_info: list of dicts describing groups where duplicates were found
        """
        cur = self.nutshell_conn.cursor()
        cur.execute(
            """
            SELECT quote, unit, amount, request, fee_reserve, created_time, state,
                   proof, checking_id, paid_time, method
            FROM melt_quotes
            """
        )
        rows = cur.fetchall()

        def norm_state(s: Optional[str]) -> str:
            return (s or "").strip().upper()

        # Group by checking_id (with special handling for null/empty)
        groups: Dict[Any, List[sqlite3.Row]] = {}
        for r in rows:
            chk = r["checking_id"]
            if chk is None or str(chk).strip() == "":
                key = ("__no_lookup__", r["quote"])  # unique per quote
            else:
                key = chk
            groups.setdefault(key, []).append(r)

        selected: List[sqlite3.Row] = []
        duplicates_info: List[Dict[str, Any]] = []

        for key, gr in groups.items():
            # Unique group or no-lookup special key
            if len(gr) == 1 or (isinstance(key, tuple) and key[0] == "__no_lookup__"):
                selected.append(gr[0])
                continue

            paid_rows = [r for r in gr if norm_state(r["state"]) == "PAID"]

            if paid_rows:
                # Choose latest PAID by paid_time (fallback created_time)
                def paid_sort_key(r: sqlite3.Row):
                    pt = r["paid_time"] if r["paid_time"] is not None else r["created_time"]
                    try:
                        return int(pt)
                    except Exception:
                        return 0
                chosen = sorted(paid_rows, key=paid_sort_key)[-1]
            else:
                # All unpaid/pending: choose latest by created_time
                def created_sort_key(r: sqlite3.Row):
                    try:
                        return int(r["created_time"])
                    except Exception:
                        return 0
                chosen = sorted(gr, key=created_sort_key)[-1]

            selected.append(chosen)

            checking_id = gr[0]["checking_id"]
            skipped = [r["quote"] for r in gr if r["quote"] != chosen["quote"]]
            duplicates_info.append({
                "checking_id": checking_id,
                "chosen_quote": chosen["quote"],
                "skipped_quotes": skipped,
                "group_size": len(gr),
            })

        return selected, duplicates_info

    def migrate_melt_quotes(self) -> int:
        """Migrate melt quotes from Nutshell to CDK format with deduplication by checking_id."""
        logger.info("Migrating melt quotes...")

        rows, duplicates_info = self._select_melt_quotes_to_migrate()

        # Log warnings about duplicates that will be skipped
        for info in duplicates_info:
            print(
                "WARNING: Multiple melt quotes share the same payment lookup id "
                f"(checking_id={info['checking_id']}). Migrating quote {info['chosen_quote']} "
                f"and skipping {info['skipped_quotes']}"
            )

        migrated_count = 0
        cdk_cursor = self.cdk_conn.cursor()

        for row in rows:
            created_time = int(row['created_time'])
            expiry_time = created_time + 157784760  # + 5 years from creation

            quote_data = {
                'id': row['quote'],
                'unit': row['unit'] or 'sat',
                'amount': row['amount'],
                'request': row['request'],
                'fee_reserve': row['fee_reserve'] or 0,
                'expiry': expiry_time,
                'state': (row['state'] or '').upper(),
                'payment_preimage': row['proof'],  # Nutshell 'proof' maps to CDK 'payment_preimage'
                'request_lookup_id': row['checking_id'],
                'created_time': created_time,
                'paid_time': row['paid_time'] if row['paid_time'] else None,
                'payment_method': (row['method'] or 'BOLT11').upper(),
                'options': None,
                'request_lookup_id_kind': 'payment_hash'
            }

            try:
                cdk_cursor.execute(
                    """
                    INSERT OR IGNORE INTO melt_quote (
                        id, unit, amount, request, fee_reserve, expiry, state,
                        payment_preimage, request_lookup_id, created_time, paid_time,
                        payment_method, options, request_lookup_id_kind
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        quote_data['id'], quote_data['unit'], quote_data['amount'],
                        quote_data['request'], quote_data['fee_reserve'], quote_data['expiry'],
                        quote_data['state'], quote_data['payment_preimage'],
                        quote_data['request_lookup_id'], quote_data['created_time'],
                        quote_data['paid_time'], quote_data['payment_method'],
                        quote_data['options'], quote_data['request_lookup_id_kind']
                    )
                )

                if cdk_cursor.rowcount > 0:
                    migrated_count += 1

            except sqlite3.Error as e:
                logger.error(f"Failed to migrate melt quote {row['quote']}: {e}")

        self.cdk_conn.commit()
        logger.info(f"Migrated {migrated_count} melt quotes")
        return migrated_count

    def create_mint_quote_payments(self) -> int:
        """Create mint quote payment records for paid quotes."""
        logger.info("Creating mint quote payment records...")
        
        nutshell_cursor = self.nutshell_conn.cursor()
        nutshell_cursor.execute("""
            SELECT quote, checking_id, paid_time, created_time, amount
            FROM mint_quotes
            WHERE state IN ('PAID', 'ISSUED')
        """)
        
        created_count = 0
        cdk_cursor = self.cdk_conn.cursor()
        
        for row in nutshell_cursor.fetchall():
            timestamp = row['paid_time']
            
            try:
                cdk_cursor.execute("""
                    INSERT OR IGNORE INTO mint_quote_payments (
                        quote_id, payment_id, timestamp, amount
                    ) VALUES (?, ?, ?, ?)
                """, (row['quote'], row['checking_id'], timestamp, row['amount']))
                
                if cdk_cursor.rowcount > 0:
                    created_count += 1
                
            except sqlite3.Error as e:
                logger.error(f"Failed to create mint quote payment record: {e}")
        
        self.cdk_conn.commit()
        logger.info(f"Created {created_count} mint quote payment records")
        return created_count
    
    def create_mint_quote_issued(self) -> int:
        """Create mint quote issuance records for issued quotes."""
        logger.info("Creating mint quote issuance records...")
        
        nutshell_cursor = self.nutshell_conn.cursor()
        nutshell_cursor.execute("""
            SELECT quote, amount, paid_time, created_time
            FROM mint_quotes
            WHERE state = 'ISSUED'
        """)
        
        created_count = 0
        cdk_cursor = self.cdk_conn.cursor()
        
        for row in nutshell_cursor.fetchall():
            timestamp = row['paid_time']
            
            try:
                cdk_cursor.execute("""
                    INSERT OR IGNORE INTO mint_quote_issued (
                        quote_id, amount, timestamp
                    ) VALUES (?, ?, ?)
                """, (row['quote'], row['amount'], timestamp))
                
                if cdk_cursor.rowcount > 0:
                    created_count += 1
                
            except sqlite3.Error as e:
                logger.error(f"Failed to create mint quote issuance record: {e}")
        
        self.cdk_conn.commit()
        logger.info(f"Created {created_count} mint quote issuance records")
        return created_count
    
    def get_migration_statistics(self) -> Dict[str, int]:
        """Get statistics about the migrated data."""
        stats = {}
        cursor = self.cdk_conn.cursor()
        
        # Count migrated keysets
        cursor.execute("SELECT COUNT(*) FROM keyset")
        stats['keysets'] = cursor.fetchone()[0]
        
        # Count proofs by state
        cursor.execute("SELECT COUNT(*) FROM proof WHERE state='SPENT'")
        stats['spent_proofs'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM proof WHERE state='PENDING'")
        stats['pending_proofs'] = cursor.fetchone()[0]
        
        # Count blind signatures
        cursor.execute("SELECT COUNT(*) FROM blind_signature")
        stats['blind_signatures'] = cursor.fetchone()[0]
        
        # Count quotes
        cursor.execute("SELECT COUNT(*) FROM mint_quote")
        stats['mint_quotes'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM melt_quote")
        stats['melt_quotes'] = cursor.fetchone()[0]
        
        # Count quote payments and issuances
        cursor.execute("SELECT COUNT(*) FROM mint_quote_payments")
        stats['mint_quote_payments'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM mint_quote_issued")
        stats['mint_quote_issued'] = cursor.fetchone()[0]
        
        return stats
    
    def print_detailed_statistics(self) -> None:
        """Print detailed migration statistics."""
        cursor = self.cdk_conn.cursor()
        
        print("\nDetailed Statistics:")
        print("=" * 50)
        
        # Keysets by unit
        print("\nKeysets by unit:")
        cursor.execute("""
            SELECT unit, COUNT(*) as count, SUM(CASE WHEN active THEN 1 ELSE 0 END) as active_count 
            FROM keyset GROUP BY unit
        """)
        for row in cursor.fetchall():
            print(f"  {row[0]}: {row[1]} total, {row[2]} active")
        
        # Quote statistics
        print("\nMint quotes by payment method:")
        cursor.execute("SELECT payment_method, COUNT(*) as count FROM mint_quote GROUP BY payment_method")
        for row in cursor.fetchall():
            print(f"  {row[0]}: {row[1]}")
        
        print("\nMelt quotes by state:")
        cursor.execute("SELECT state, COUNT(*) as count FROM melt_quote GROUP BY state")
        for row in cursor.fetchall():
            print(f"  {row[0]}: {row[1]}")
    
    def verify_migrations(self) -> bool:
        """
        Verify that all migrations completed successfully by ensuring that all
        migrateable data from Nutshell (>= 0.16) is present in CDK.
        CDK may contain additional entries that are not in Nutshell, but not vice versa.
        
        Returns:
            bool: True if all verifications pass, False otherwise
        """
        logger.info("Starting migration verification...")
        
        verification_results = []
        all_verified = True
        
        nutshell_cursor = self.nutshell_conn.cursor()
        cdk_cursor = self.cdk_conn.cursor()
        
        # Verification 1: Keysets
        logger.info("Verifying keysets migration...")

        # Get CDK keysets as a set
        cdk_keysets = set()
        cdk_cursor.execute("SELECT id FROM keyset")
        for row in cdk_cursor.fetchall():
            cdk_keysets.add(row['id'])
        
        # Check that all migrateable Nutshell keysets (>= 0.16) exist in CDK
        nutshell_cursor.execute("""
            SELECT version, id FROM keysets 
            WHERE version IS NOT NULL
        """)
        
        migrateable_keysets = 0
        missing_keysets = []
        for row in nutshell_cursor.fetchall():
            if self.is_version_gte_015(row['version']):
                migrateable_keysets += 1
                if row['id'] not in cdk_keysets:
                    missing_keysets.append(row['id'])
        
        keysets_verified = len(missing_keysets) == 0
        verification_results.append(("Keysets", migrateable_keysets, len(cdk_keysets), keysets_verified))
        if not keysets_verified:
            all_verified = False
            logger.error(f"Missing keysets in CDK: {missing_keysets}")
        
        # Verification 2: Spent Proofs (proofs_used -> proof with state='SPENT')
        logger.info("Verifying spent proofs migration...")
        
        # Get all spent proofs from CDK
        cdk_spent_proofs = set()
        cdk_cursor.execute("SELECT secret, keyset_id FROM proof WHERE state='SPENT'")
        for row in cdk_cursor.fetchall():
            cdk_spent_proofs.add((row['secret'], row['keyset_id']))
        
        # Check all migrateable Nutshell spent proofs exist in CDK
        nutshell_cursor.execute("""
            SELECT pu.secret, pu.id as keyset_id, k.version 
            FROM proofs_used pu
            JOIN keysets k ON k.id = pu.id
            WHERE k.version IS NOT NULL
        """)
        
        migrateable_spent = 0
        missing_spent = []
        for row in nutshell_cursor.fetchall():
            if self.is_version_gte_015(row['version']):
                migrateable_spent += 1
                proof_key = (row['secret'], row['keyset_id'])
                if proof_key not in cdk_spent_proofs:
                    missing_spent.append(proof_key)
        
        spent_verified = len(missing_spent) == 0
        verification_results.append(("Spent Proofs", migrateable_spent, len(cdk_spent_proofs), spent_verified))
        if not spent_verified:
            all_verified = False
            logger.error(f"Missing spent proofs in CDK: {len(missing_spent)} out of {migrateable_spent}")
        
        # Verification 3: Pending Proofs (proofs_pending -> proof with state='PENDING')
        logger.info("Verifying pending proofs migration...")
        
        # Get all pending proofs from CDK
        cdk_pending_proofs = set()
        cdk_cursor.execute("SELECT secret, keyset_id FROM proof WHERE state='PENDING'")
        for row in cdk_cursor.fetchall():
            cdk_pending_proofs.add((row['secret'], row['keyset_id']))
        
        # Check all migrateable Nutshell pending proofs exist in CDK
        nutshell_cursor.execute("""
            SELECT pp.secret, pp.id as keyset_id, k.version 
            FROM proofs_pending pp
            JOIN keysets k ON k.id = pp.id
            WHERE k.version IS NOT NULL
        """)
        
        migrateable_pending = 0
        missing_pending = []
        for row in nutshell_cursor.fetchall():
            if self.is_version_gte_015(row['version']):
                migrateable_pending += 1
                proof_key = (row['secret'], row['keyset_id'])
                if proof_key not in cdk_pending_proofs:
                    missing_pending.append(proof_key)
        
        pending_verified = len(missing_pending) == 0
        verification_results.append(("Pending Proofs", migrateable_pending, len(cdk_pending_proofs), pending_verified))
        if not pending_verified:
            all_verified = False
            logger.error(f"Missing pending proofs in CDK: {len(missing_pending)} out of {migrateable_pending}")
        
        # Verification 4: Promises (promises -> blind_signature)
        logger.info("Verifying promises migration...")
        
        # Get all blind signatures from CDK (using blinded_message and keyset_id as key)
        cdk_signatures = set()
        cdk_cursor.execute("SELECT blinded_message, keyset_id FROM blind_signature")
        for row in cdk_cursor.fetchall():
            cdk_signatures.add((row['blinded_message'], row['keyset_id']))
        
        # Check all migrateable Nutshell promises exist in CDK
        nutshell_cursor.execute("""
            SELECT p.b_, p.id as keyset_id, k.version 
            FROM promises p
            JOIN keysets k ON k.id = p.id
            WHERE k.version IS NOT NULL
        """)
        
        migrateable_promises = 0
        missing_promises = []
        for row in nutshell_cursor.fetchall():
            if self.is_version_gte_015(row['version']):
                # Convert hex to blob to match CDK format
                blinded_message_blob = self.hex_to_blob(row['b_'])
                if blinded_message_blob:
                    migrateable_promises += 1
                    promise_key = (blinded_message_blob, row['keyset_id'])
                    if promise_key not in cdk_signatures:
                        missing_promises.append(promise_key)
        
        promises_verified = len(missing_promises) == 0
        verification_results.append(("Promises/Blind Signatures", migrateable_promises, len(cdk_signatures), promises_verified))
        if not promises_verified:
            all_verified = False
            logger.error(f"Missing promises in CDK: {len(missing_promises)} out of {migrateable_promises}")
        
        # Verification 5: Mint Quotes
        logger.info("Verifying mint quotes migration...")
        
        # Get all mint quotes from CDK
        cdk_mint_quotes = set()
        cdk_cursor.execute("SELECT id FROM mint_quote")
        for row in cdk_cursor.fetchall():
            cdk_mint_quotes.add(row['id'])
        
        # Check all Nutshell mint quotes exist in CDK
        nutshell_cursor.execute("SELECT quote FROM mint_quotes")
        nutshell_mint_quotes = set()
        missing_mint_quotes = []
        for row in nutshell_cursor.fetchall():
            nutshell_mint_quotes.add(row['quote'])
            if row['quote'] not in cdk_mint_quotes:
                missing_mint_quotes.append(row['quote'])
        
        mint_quotes_verified = len(missing_mint_quotes) == 0
        verification_results.append(("Mint Quotes", len(nutshell_mint_quotes), len(cdk_mint_quotes), mint_quotes_verified))
        if not mint_quotes_verified:
            all_verified = False
            logger.error(f"Missing mint quotes in CDK: {len(missing_mint_quotes)} out of {len(nutshell_mint_quotes)}")
        
        # Verification 6: Melt Quotes
        logger.info("Verifying melt quotes migration...")
        
        # Get all melt quotes from CDK
        cdk_melt_quotes = set()
        cdk_cursor.execute("SELECT id FROM melt_quote")
        for row in cdk_cursor.fetchall():
            cdk_melt_quotes.add(row['id'])
        
        # Determine which Nutshell melt quotes should have been migrated (dedup by checking_id)
        selected_rows, _dup_info = self._select_melt_quotes_to_migrate()
        expected_melt_ids = {r['quote'] for r in selected_rows}
        missing_melt_quotes = [qid for qid in expected_melt_ids if qid not in cdk_melt_quotes]
        
        melt_quotes_verified = len(missing_melt_quotes) == 0
        verification_results.append(("Melt Quotes", len(expected_melt_ids), len(cdk_melt_quotes), melt_quotes_verified))
        if not melt_quotes_verified:
            all_verified = False
            logger.error(f"Missing melt quotes in CDK: {len(missing_melt_quotes)} out of {len(expected_melt_ids)}")
        
        # Verification 7: Mint Quote Payments
        logger.info("Verifying mint quote payments migration...")
        
        # Get all mint quote payments from CDK
        cdk_payments = set()
        cdk_cursor.execute("SELECT quote_id FROM mint_quote_payments")
        for row in cdk_cursor.fetchall():
            cdk_payments.add(row['quote_id'])
        
        # Check all Nutshell paid/issued mint quotes have payments in CDK
        nutshell_cursor.execute("""
            SELECT quote FROM mint_quotes 
            WHERE state IN ('paid', 'issued')
        """)
        nutshell_paid_quotes = set()
        missing_payments = []
        for row in nutshell_cursor.fetchall():
            nutshell_paid_quotes.add(row['quote'])
            if row['quote'] not in cdk_payments:
                missing_payments.append(row['quote'])
        
        payments_verified = len(missing_payments) == 0
        verification_results.append(("Mint Quote Payments", len(nutshell_paid_quotes), len(cdk_payments), payments_verified))
        if not payments_verified:
            all_verified = False
            logger.error(f"Missing mint quote payments in CDK: {len(missing_payments)} out of {len(nutshell_paid_quotes)}")
        
        # Verification 8: Mint Quote Issued
        logger.info("Verifying mint quote issued migration...")
        
        # Get all mint quote issued from CDK
        cdk_issued = set()
        cdk_cursor.execute("SELECT quote_id FROM mint_quote_issued")
        for row in cdk_cursor.fetchall():
            cdk_issued.add(row['quote_id'])
        
        # Check all Nutshell issued mint quotes have issued records in CDK
        nutshell_cursor.execute("""
            SELECT quote FROM mint_quotes 
            WHERE state = 'issued'
        """)
        nutshell_issued_quotes = set()
        missing_issued = []
        for row in nutshell_cursor.fetchall():
            nutshell_issued_quotes.add(row['quote'])
            if row['quote'] not in cdk_issued:
                missing_issued.append(row['quote'])
        
        issued_verified = len(missing_issued) == 0
        verification_results.append(("Mint Quote Issued", len(nutshell_issued_quotes), len(cdk_issued), issued_verified))
        if not issued_verified:
            all_verified = False
            logger.error(f"Missing mint quote issued in CDK: {len(missing_issued)} out of {len(nutshell_issued_quotes)}")
        
        # Print verification results
        print("\nMigration Verification Results:")
        print("=" * 80)
        print(f"{'Migration Type':<25} {'Nutshell Count':<15} {'CDK Count':<12} {'Status':<10}")
        print("-" * 80)
        
        for migration_type, nutshell_count, cdk_count, verified in verification_results:
            status = "✓ PASS" if verified else "✗ FAIL"
            status_color = status  # Could add colors here if needed
            print(f"{migration_type:<25} {nutshell_count:<15} {cdk_count:<12} {status_color:<10}")
        
        print("-" * 80)
        overall_status = "✓ ALL VERIFIED" if all_verified else "✗ VERIFICATION FAILED"
        print(f"Overall Status: {overall_status}")
        
        if not all_verified:
            print("\nVerification failed! Please check the migration logic and database contents.")
            logger.error("Migration verification failed")
        else:
            print("\nAll migrations verified successfully!")
            logger.info("Migration verification completed successfully")
        
        return all_verified
    '''
    def print_verification_queries(self) -> None:
        """Print verification queries that can be run manually."""
        print("\nVerification queries you can run:")
        print("=" * 50)
        
        queries = [
            ("Check keyset distribution", "SELECT unit, COUNT(*) as count FROM keyset GROUP BY unit;"),
            ("Check proof state distribution", "SELECT state, COUNT(*) as count FROM proof GROUP BY state;"),
            ("Check orphaned proofs", "SELECT COUNT(*) as orphaned_proofs FROM proof WHERE keyset_id NOT IN (SELECT id FROM keyset);"),
            ("Check orphaned signatures", "SELECT COUNT(*) as orphaned_signatures FROM blind_signature WHERE keyset_id NOT IN (SELECT id FROM keyset);"),
            ("Show sample keysets", "SELECT id, unit, active, derivation_path, derivation_path_index, datetime(valid_from, 'unixepoch') as valid_from_date FROM keyset LIMIT 5;"),
            ("Mint quote statistics", "SELECT payment_method, COUNT(*) as count, SUM(amount_paid) as total_paid, SUM(amount_issued) as total_issued FROM mint_quote GROUP BY payment_method;"),
            ("Melt quote statistics", "SELECT state, COUNT(*) as count, SUM(amount) as total_amount, SUM(fee_reserve) as total_fees FROM melt_quote GROUP BY state;"),
            ("Sample mint quotes", "SELECT id, unit, amount, amount_paid, amount_issued, payment_method, datetime(created_time, 'unixepoch') as created FROM mint_quote LIMIT 5;"),
            ("Sample melt quotes", "SELECT id, unit, amount, fee_reserve, state, payment_method, datetime(created_time, 'unixepoch') as created FROM melt_quote LIMIT 5;"),
        ]
        
        for description, query in queries:
            print(f"\n# {description}:")
            print(f"sqlite3 '{self.cdk_db_path}' \"{query}\"")
    '''
    
    def run_migration(self) -> None:
        """Run the complete migration process."""
        logger.info("Starting migration from Nutshell to CDK...")
        logger.info(f"Source (Nutshell): {self.nutshell_db_path}")
        logger.info(f"Target (CDK): {self.cdk_db_path}")
        
        try:
            # Validate inputs and connect
            self.validate_inputs()
            self.connect_databases()

            # Pre-check: warn about incompatible keysets (version < 0.16)
            self.warn_incompatible_keysets()
            
            # Begin migration in transaction
            self.cdk_conn.execute("BEGIN TRANSACTION")
            
            # Run migration steps
            keyset_count = self.migrate_keysets()
            spent_count = self.migrate_proofs_used()
            pending_count = self.migrate_proofs_pending()
            promise_count = self.migrate_promises()
            mint_quote_count = self.migrate_mint_quotes()
            melt_quote_count = self.migrate_melt_quotes()
            payment_count = self.create_mint_quote_payments()
            issuance_count = self.create_mint_quote_issued()
            
            # Commit transaction
            self.cdk_conn.commit()
            
            logger.info("Migration completed successfully!")
            
            # Print statistics
            print("\nMigration Statistics:")
            print("=" * 50)
            print(f"Migrated keysets: {keyset_count}")
            print(f"Migrated spent proofs: {spent_count}")
            print(f"Migrated pending proofs: {pending_count}")
            print(f"Migrated promises (blind signatures): {promise_count}")
            print(f"Migrated mint quotes: {mint_quote_count}")
            print(f"Migrated melt quotes: {melt_quote_count}")
            print(f"Migrated mint quote payments: {payment_count}")
            print(f"Migrated mint quote issuances: {issuance_count}")
            
            self.print_detailed_statistics()
            
        except Exception as e:
            # Rollback on error
            if self.cdk_conn:
                self.cdk_conn.rollback()
            logger.error(f"Migration failed: {e}")
            raise
        
        finally:
            self.close_connections()


def main():
    """Main entry point for the migration script."""
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python3 nutshell_to_cdk_migration.py <nutshell_db_path> <cdk_db_path> [--verify-only]")
        print("  nutshell_db_path: Path to the Nutshell SQLite database")
        print("  cdk_db_path: Path to the CDK SQLite database")
        print("  --verify-only: Only run verification without migration")
        sys.exit(1)
    
    nutshell_db_path = sys.argv[1]
    cdk_db_path = sys.argv[2]
    verify_only = len(sys.argv) == 4 and sys.argv[3] == '--verify-only'
    
    try:
        migrator = NutshellToCDKMigrator(nutshell_db_path, cdk_db_path)
        
        if verify_only:
            print("Running migration verification only...")
            migrator.validate_inputs()
            migrator.connect_databases()
            verification_passed = migrator.verify_migrations()
            migrator.close_connections()
            
            if not verification_passed:
                sys.exit(1)
            return
        
        print("\nIMPORTANT NOTES:")
        print("=" * 50)
        notes = [
            "This migration only includes keysets with version >= 0.15 from Nutshell",
            "This migration does NOT include auth tables",
            "The blind_signature table uses 'blinded_message' column (renamed from 'y' in recent CDK versions)",
            "DLEQ proofs (dleq_e, dleq_s) are migrated if available in Nutshell promises",
            "Derivation paths are split: base path goes to 'derivation_path', counter goes to 'derivation_path_index'",
            "Please verify the migrated data before using it in production",
            "If multiple Nutshell melt quotes share the same payment lookup id (checking_id), the migrator will: pick a PAID one if present (latest by paid_time), otherwise pick the latest by created_time; the rest will be skipped and listed as warnings.",
        ]
        
        for i, note in enumerate(notes, 1):
            print(f"{i:2d}. {note}")

        proceed = input("\nDo you wish to proceed with migration? [Y/n]: ")

        if proceed == 'Y':
            migrator.run_migration()
            
            # After migration, ask if user wants to run verification
            verify = input("\nWould you like to run verification of the migration? [Y/n]: ")
            if verify == 'Y':
                print("\nRunning migration verification...")
                migrator.validate_inputs()
                migrator.connect_databases()
                verification_passed = migrator.verify_migrations()
                migrator.close_connections()
                
                if not verification_passed:
                    print("\nWARNING: Migration verification failed! Please review the results above.")
                    sys.exit(1)

    except Exception as e:
        logger.error(f"Migration script failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
