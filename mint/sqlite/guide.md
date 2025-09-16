## How to perform a SQLITE to SQLITE migration

### Before you start

1. **Make sure you a have the latest CDK**: earlier versions might not support a direct seed configuration and base64 quote IDs.
2. **Nutshell keysets that were produced using a version of < 0.15 will be ignored**: "pre 0.15" keysets are fundamentally incompatible with the derivation process the CDK uses. Be sure you've already rotated out of any "pre 0.15" keysets and some time has passed, allowing users time to swap their ecash out of those keysets.

### Preparations

1. In the `config.toml`, under the \[info\] section, set `seed` to your `MINT_PRIVATE_KEY` value used for Nutshell. Alternatively you  could set the `CDK_MINTD_SEED` environment variable.  For migrated mints, you do not need the mnemonic key in config.toml.
2. The sqlite database for your  `cdk-mintd` Mint has to exist, therefore run `cdk-mintd` with the sqlite engine configuration at least once.  By default, this will create cdk-mintd.sqlite.

### Run the script

1. Run the script `python3 nutshell_to_cdk_sqlite_migration_noauth.py <nutshell_sqlite_db> <cdk_sqlite_db>`
2. Say yes to the prompt:
```
IMPORTANT NOTES:
==================================================
 1. This migration only includes keysets with version >= 0.15 from Nutshell
 2. This migration does NOT include auth tables
 3. The blind_signature table uses 'blinded_message' column (renamed from 'y' in recent CDK versions)
 4. DLEQ proofs (dleq_e, dleq_s) are migrated if available in Nutshell promises
 5. Derivation paths are split: base path goes to 'derivation_path', counter goes to 'derivation_path_index'
 6. Please verify the migrated data before using it in production

Do you wish to proceed with migration? [Y/n]: Y
```
3. Once the migration terminates, say yes to verify it:
```
Migration Statistics:
==================================================
Migrated keysets: 3
Migrated spent proofs: 2151
Migrated pending proofs: 0
Migrated promises (blind signatures): 7888
Migrated mint quotes: 1394
Migrated melt quotes: 94
Migrated mint quote payments: 1394
Migrated mint quote issuances: 1084

Detailed Statistics:
==================================================

Keysets by unit:
  auth: 1 total, 1 active 
  msat: 1 total, 1 active
  sat: 2 total, 2 active
  usd: 1 total, 1 active

Mint quotes by payment method:
  BOLT11: 1394

Melt quotes by state:
  PAID: 48
  UNPAID: 46

Would you like to run verification of the migration? [Y/n]: Y
```

4. If the verification succeeded, your migrated database is ready.
```
--------------------------------------------------------------------------------
Overall Status: ✓ ALL VERIFIED

```
5. Start the cdk-mintd and smoketest funcitonlaity such as send, receive, mint, melt, and checking transaciton histories.
   
