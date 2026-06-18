# Wallet ↔ Wallet PQ transfers (testnet PoC)

Extends the wallet-native post-quantum (PQ) spend from self-spend-of-coinbase to
**wallet-to-wallet** transfers. Builds on `pqc/testnet-poc`. Testnet only /
experimental: the lattice ring signature is unaudited and the bootstrap relies on a
fixed testnet KEM keypair. **Not for mainnet funds.**

## What changed

All work is in the wallet/RPC front-end layer. The shared builder
(`cn::buildPqSpendTransaction`, `src/CryptoNoteCore/PqSpendBuilder.*`), consensus,
serialization, and `pq_injector` are **unchanged** — no crypto was touched.

| File | Change |
| --- | --- |
| `src/Rpc/PqSpendClient.{h,cpp}` | `pqSpendViaDaemon` now takes a **list** of candidate KEM secret keys and an explicit recipient KEM pubkey. |
| `src/ConcealWallet/ConcealWallet.{h,cpp}` | New `pq_address`, `pq_receive`; generalized `pq_transfer`; `pq_balance [mine]`. |
| `src/PaymentGate/WalletService.cpp` | Updated to the new `pqSpendViaDaemon` signature (passes `{PQ_TESTNET_KEM_SK}` as before). |

## Wallet PQ KEM key derivation (mnemonic-restorable)

A wallet's PQ KEM keypair is the **address-bearing receive key**. It is derived
deterministically from the wallet's legacy spend secret key so the same mnemonic
always reproduces the same PQ address:

```
masterSeed   = m_wallet->getAddressSpendKey(0).secretKey   // 32-byte legacy spend secret
kemSeed      = cn_fast_hash("ccx-pq-kem-acct" || masterSeed) // domain-separated (cn::PqAccount)
(kemPk,kemSk)= ccx_pq_kem_keygen_det(kemSeed)                // FIPS-203 ML-KEM-768, deterministic
```

The wallet reuses `cn::PqAccount::generateFromSeed` verbatim (it owns the domain
discipline), so the wallet's derived address is byte-identical to what `PqAccount`
produces. Concentrated in `conceal_wallet::getPqAccountKeys()`.

The fixed testnet KEM keypair (`cn::PQ_TESTNET_KEM_SK/PK`) owns the **coinbase**
outputs ("Option B" bootstrap); a wallet's **own** seed-derived KEM secret owns
outputs sent to its PQ address.

## Generalized `pqSpendViaDaemon`

```cpp
bool pqSpendViaDaemon(platform_system::Dispatcher& dispatcher,
                      const std::string& daemonHost,
                      uint16_t daemonPort,
                      uint64_t amount,
                      uint64_t fee,
                      uint32_t ringSize,
                      const std::vector<std::vector<uint8_t>>& candidateKemSecretKeys, // NEW
                      const std::vector<uint8_t>& recipientKemPubKey,                  // now explicit
                      std::string& outTxHashHex,
                      std::string& outStatus,
                      std::string& err);
```

- **`candidateKemSecretKeys`** — a list of ML-KEM-768 secret keys that may own a
  spendable signer output. Empty entries are filtered out; an all-empty list is an
  error. In the random-signer attempt loop, for each chosen signer the ring is
  assembled once and then each candidate secret is handed to the builder in turn.
  A wrong secret makes the builder's KEM scan fail (`output not ours`) and the next
  candidate is tried; if none own the signer, the loop moves to a different signer.
  This lets one wallet spend **both** the fixed-key coinbase outputs **and** outputs
  received to its own address. The random-signer + decoy + retry + relay-status-check
  logic is otherwise unchanged.
- **`recipientKemPubKey`** — the real recipient's ML-KEM-768 public key. Non-empty =
  real scannable stealth output. Empty would burn the funds (injector-only A/B path);
  the wallet front-ends never pass empty.

`PqSpendClient.cpp` no longer references `pq_testnet_kem_keypair.h`; the caller now
owns the candidate list.

## New / changed CLI commands

- **`pq_address`** — derive and print the wallet's deterministic `ctp…` PQ address
  (carries its seed-derived KEM pubkey). Same wallet → same address.
- **`pq_transfer <pq_address | self> [ringSize] [fee]`** — parse the recipient
  address → KEM pubkey, then `pqSpendViaDaemon` with candidate secrets
  `{ own KEM secret, fixed testnet KEM secret }`. `self` sends back to the wallet's
  own PQ pubkey. Accepts testnet (`ctp`/`cth`) and mainnet (`ccxp`/`ccxh`) PQ/hybrid
  prefixes; `parsePqAccountAddressString` pins version + scheme ids + KEM-key length.
  Defaults: `ringSize=4`, `fee=1000`.
- **`pq_receive`** — fetch `get_pq_outputs` for the candidate amounts, scan each
  entry's `kemCt` with the wallet's own KEM secret (and the fixed testnet secret), and
  list the outputs that belong to this wallet (global index, amount, lock state). Scan
  reuses the builder's path: `ccx_pq_kem_scan` → `ccx_pq_keygen` → compare the
  recovered one-time pubkey to the on-chain output key. Read-only; recovered secret
  material is wiped immediately.
- **`pq_balance [mine]`** — unchanged default (all unlocked PQ outputs); `mine`
  counts only outputs this wallet can scan (best-effort).

### Candidate amounts

`get_pq_outputs` enumerates per amount, so `pq_balance` / `pq_receive` query
`PQ_TESTNET_COINBASE_AMOUNT` plus the post-fee denominations a default-fee spend
produces (`coinbase − {1000,100,10}`). Amounts with no outputs return empty and are
harmless.

## Deferred / notes

- `pq_receive` / `pq_balance mine` only see the **post-fee denominations** for the
  default fees baked into `pqCandidateAmounts()`. A spend with an unusual fee produces
  an output amount not in that list and would not be enumerated. A fully general view
  would need the daemon to report the set of distinct PQ amounts it holds; deferred.
- No end-to-end testnet run was performed here (per request); wallet↔wallet is to be
  verified separately.
