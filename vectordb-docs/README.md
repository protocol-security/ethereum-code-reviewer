# Vector Database Documentation

Documentation corpus for building a vector database of Ethereum protocol knowledge.

## Idea

A knowledge base organised by protocol layer (execution/consensus) and category (EIPs, specs, vulnerabilities).

## Sources

- **EIPs**: [ethereum/EIPs](https://github.com/ethereum/EIPs) - Manually retrieved and organised by fork
- **Consensus Specs**: [ethereum/consensus-specs](https://github.com/ethereum/consensus-specs)
- **Vulnerabilities**: [ethereum/public-disclosures](https://github.com/ethereum/public-disclosures)

## Structure

```
docs/
├── execution/
│   ├── eips/{fork}/
│   └── vulnerabilities/
└── consensus/
    ├── eips/{fork}/
    ├── specs/{fork}/
    └── vulnerabilities/
```

## Update Specifications

To update the specifications with the latest changes from the original [repository](https://github.com/ethereum/consensus-specs), please use the following command:

```bash
scripts/sync-consensus-specs.sh
```

## Contributing

If anything is missing or incorrect, please open a PR.