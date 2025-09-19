# Anonymous Attestation

A privacy-preserving attestation system built on the Stacks blockchain using Clarity smart contracts, enabling users to prove attributes without revealing sensitive personal information.

## Overview

This system implements a selective disclosure attestation platform that allows users to obtain privacy-preserving credentials and selectively disclose attributes on-chain without revealing raw data. The system uses a hybrid approach combining on-chain credential registries with off-chain proof generation.

## Architecture

### Core Components

1. **Selective Disclosure Tokens (MVP)**
   - Non-transferable attestation tokens (SBT-like)
   - On-chain credential registry with issuer verification
   - Selective proof generation for privacy-preserving attribute disclosure

2. **External Proof Verification Bridge**
   - Off-chain ZK proof generation and verification
   - Trusted verifier nodes post succinct attestations to blockchain
   - Pragmatic approach avoiding expensive on-chain ZK verification

3. **Revocation & Freshness System**
   - Merkle tree-based credential status tracking
   - Periodic updates to revocation lists
   - Time-bounded credential validity

4. **Proof-of-Possession Flow**
   - Anonymous wallet control verification
   - Ephemeral challenge-response system
   - Zero-knowledge wallet-credential binding

## Features

### Current (MVP)
- ✅ **Selective Disclosure Tokens**: Issue privacy-preserving credentials
- ✅ **Issuer Registry**: Manage trusted credential issuers
- ✅ **Attribute Verification**: Verify claims without revealing raw data
- ✅ **Revocation Support**: Track and verify credential status
- ✅ **Time-based Validity**: Implement credential expiration

### Planned (Next Steps)
- 🔄 **Decentralized Verifier Network**: Multi-node proof verification
- 🔄 **Lightweight On-chain Circuits**: Simple arithmetic verification
- 🔄 **Enhanced Privacy APIs**: Advanced selective disclosure

### Research (Long Term)
- 🔬 **Full On-chain ZK Verification**: Native STARK/SNARK support
- 🔬 **Anonymous Reputation**: Privacy-preserving scoring system
- 🔬 **Recovery & Portability**: Cross-wallet credential migration

## Smart Contract Structure

### Core Contract: `selective-disclosure-registry`

#### Data Storage
- **Issuer Registry**: Maps of verified credential issuers
- **Credential Types**: Supported attribute claim types
- **Merkle Anchors**: Revocation status tracking roots
- **Attestations**: Verified proof records with expiration

#### Key Functions
- `register-issuer`: Add trusted credential issuer
- `issue-credential-type`: Define new attribute claim type
- `update-merkle-anchor`: Update revocation status root
- `verify-attestation`: Validate selective disclosure proof
- `check-credential-status`: Query credential validity

## Installation & Setup

### Prerequisites
- [Clarinet](https://docs.hiro.so/clarinet) v2.0+
- Node.js 18+
- Stacks CLI

### Quick Start

```bash
# Clone repository
git clone https://github.com/your-org/anonymous-attestation
cd anonymous-attestation

# Install dependencies
clarinet requirements

# Run tests
clarinet test

# Deploy to testnet
clarinet deploy --testnet
```

### Project Structure

```
anonymous-attestation/
├── contracts/
│   ├── selective-disclosure-registry.clar    # Main contract
│   └── traits/
│       └── sip-009-nft-trait.clar           # NFT trait for tokens
├── tests/
│   ├── selective-disclosure-registry_test.ts
│   └── integration/
├── settings/
│   ├── Devnet.toml
│   └── Testnet.toml
├── scripts/
│   ├── deploy.ts
│   └── setup-issuers.ts
└── docs/
    ├── API.md
    └── integration-guide.md
```

## Usage Examples

### Register a Credential Issuer

```clarity
;; Register university as age credential issuer
(contract-call? .selective-disclosure-registry register-issuer 
  'SP1HTBVD3JG9C05J7HBJTHGR0GGW7KX975CN0QDN
  "university-x"
  (list "age-verification"))
```

### Issue Credential Type

```clarity
;; Define age verification credential type
(contract-call? .selective-disclosure-registry issue-credential-type
  u1
  "age-gte-18"
  "Age greater than or equal to 18 years")
```

### Verify Attestation

```clarity
;; Verify user's age proof without revealing exact age
(contract-call? .selective-disclosure-registry verify-attestation
  'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7  ;; user
  u1                                            ;; credential-type-id  
  0x1234...                                    ;; proof-hash
  u1672531200)                                 ;; valid-until
```

## Privacy Guarantees

### What's Private
- ✅ Raw attribute values (age, income, location, etc.)
- ✅ User identity-credential linkage on-chain
- ✅ Exact proof generation timing
- ✅ Credential usage patterns across dApps

### What's Public
- ⚠️ Credential type being verified
- ⚠️ Verification success/failure status
- ⚠️ Approximate timing of verifications
- ⚠️ Issuer identity and reputation

## Security Considerations

### Trust Assumptions
- **Issuer Honesty**: Credential issuers verify attributes correctly
- **Verifier Network**: Off-chain proof verification nodes operate honestly
- **Cryptographic Primitives**: Underlying ZK proof systems are secure

### Known Limitations
- No on-chain ZK verification (performance limitation)
- Trusted verifier network (centralization risk)
- Limited to simple attribute claims (complexity constraint)

## Integration Guide

### For dApp Developers

1. **Check User Credentials**
```javascript
// Query if user has valid age verification
const hasAgeProof = await callReadOnlyFunction({
  contractAddress: 'SP...',
  contractName: 'selective-disclosure-registry',
  functionName: 'has-valid-attestation',
  functionArgs: [principalCV(userAddress), uintCV(1)],
});
```

2. **Require Proof Verification**
```clarity
;; In your dApp contract
(define-public (age-gated-function)
  (let ((has-age-proof (contract-call? .selective-disclosure-registry 
                        has-valid-attestation tx-sender u1)))
    (asserts! has-age-proof (err u403))
    ;; Your age-gated logic here
    (ok true)))
```

### For Wallet Integrations

See [Integration Guide](docs/integration-guide.md) for detailed wallet integration patterns.

## Contributing

### Development Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-feature`
3. Write tests for new functionality
4. Implement feature with proper error handling
5. Run full test suite: `clarinet test`
6. Submit pull request

### Testing Standards
- Unit tests for all public functions
- Integration tests for complete workflows
- Error case coverage >90%
- Gas usage optimization

## API Documentation

Full API documentation available at [docs/API.md](docs/API.md).

### Key Endpoints
- `/verify` - Verify selective disclosure proof
- `/status` - Check credential status
- `/issuers` - List registered issuers
- `/types` - Available credential types

## Roadmap

### Q1 2025
- [ ] Multi-verifier consensus mechanism
- [ ] Enhanced privacy-preserving APIs
- [ ] Cross-chain credential portability research

### Q2 2025
- [ ] Lightweight on-chain circuit verification
- [ ] Anonymous reputation system prototype
- [ ] Recovery mechanism implementation

### Q3-Q4 2025
- [ ] Full on-chain ZK verification (research dependent)
- [ ] Decentralized issuer governance
- [ ] Production mainnet deployment

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support & Community

- **Documentation**: [docs.anonymous-attestation.io](https://docs.anonymous-attestation.io)
- **Discord**: [discord.gg/anonymous-attestation](https://discord.gg/anonymous-attestation)
- **GitHub Issues**: Report bugs and request features
- **Twitter**: [@anon_attestation](https://twitter.com/anon_attestation)

---

**Disclaimer**: This project is experimental software. Use at your own risk. Not audited for production use.
