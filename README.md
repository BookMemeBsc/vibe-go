# VIBE AI Blockchain

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![Status](https://img.shields.io/badge/status-development-yellow.svg)
![Go Version](https://img.shields.io/badge/Go-1.18+-blue.svg)
![Updated](https://img.shields.io/badge/updated-YYYY--MM--DD-brightgreen.svg) 
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Welcome to the VIBE AI Blockchain project – a demonstration of a blockchain implementation significantly crafted with the assistance of AI. This project serves as an exploration into AI-driven development within the blockchain space, leveraging Go for its core implementation.

## ✨ The VIBE AI Vision

The core idea behind VIBE AI Blockchain is to showcase the potential of AI as a co-developer. Much of the foundational code, data structures, and logic were generated or refined through interaction with AI, making it potentially the first "Vibe Coded" blockchain. This project explores:

-   **AI-Assisted Code Generation:** Utilizing AI to write boilerplate code, complex algorithms (like PoW validation, difficulty adjustment), and data serialization.
-   **Rapid Prototyping:** Accelerating the development lifecycle from concept to a functional blockchain core.
-   **Learning & Exploration:** Serving as a testbed for understanding blockchain fundamentals built with modern AI tooling.

## 🚀 Key Features

The VIBE AI Blockchain implements several core blockchain concepts:

*   **Proof-of-Work (PoW):** Secures the network using a PoW consensus mechanism.
*   **Block Structure:** Standard block format including timestamp, previous block hash, transactions, height, target, nonce, and hash.
*   **Transaction Model:** Utilizes a UTXO (Unspent Transaction Output) model, similar to Bitcoin. Includes basic transaction creation and validation.
*   **Wallet Integration:** Basic wallet functionality for managing keys and addresses (using Base58Check encoding).
*   **Persistence:** Uses BadgerDB for efficient on-disk storage of the blockchain data.
*   **Difficulty Adjustment:** Dynamically adjusts the PoW difficulty every `difficultyAdjustmentInterval` (currently 100 blocks) based on the time taken to mine previous blocks, targeting an average block time (`targetBlockTimeSeconds`, currently 10 seconds).
*   **Block Rewards:** Implements a block reward system (`InitialBlockReward`) with a halving mechanism (`blockRewardHalvingInterval`).
*   **Hardcoded Genesis Block:** Initializes the chain with a predefined genesis block.
*   **Blockchain Iteration:** Provides an iterator for traversing blocks from the tip backwards.
*   **Core Functions:** Includes functions for adding blocks, finding transactions, calculating balances, and finding spendable outputs.

## 🏁 Getting Started

Follow these steps to get the VIBE AI Blockchain node running on your local machine.

1.  **Prerequisites:**
    *   Go (version 1.18 or later) installed: [https://go.dev/doc/install](https://go.dev/doc/install)
    *   Git installed: [https://git-scm.com/book/en/v2/Getting-Started-Installing-Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)

2.  **Clone the Repository:**
    ```bash
    git clone https://github.com/cryptoaaron/vibe-go.git # Replace with the actual repo URL
    cd vibe-go
    ```

3.  **Build the Project:**
    Compile the Go code to create the executable.
    ```bash
    make 
    mkdir data # make data directory for wallet
   ./vibe-cli createwallet
    ```

4.  **Run the Node (Example):**
    Start a blockchain node. The specific command might depend on the final implementation in `cmd/node`. A typical invocation might look like:
    ```bash
    # use wallet generated in above command:
    ./vibe-node -mine -mineraddress <wallet> -port 9001
    ```
    *(Check the `cmd/node/main.go` or related files for specific command-line arguments if required, e.g., for setting ports or joining a network).*

5.  **Interact (If CLI is available):**
    If a command-line interface (`vibe-cli`) is built, you can use it to interact with the running node (or directly with the blockchain data). Examples (these might vary):
    ```bash
    # Get balance for an address
    ./vibe-cli getbalance -address YOUR_ADDRESS 

    # Send VIBE
    ./vibe-cli send -from FROM_ADDRESS -to TO_ADDRESS -amount AMOUNT

    # Print the chain
    ./vibe-cli printchain
    ```

## 🤝 Contributing

Contributions are welcome! As this project emphasizes AI-assisted development, contributions could involve:

*   Refining AI-generated code.
*   Adding new features (e.g., networking, improved CLI, smart contracts).
*   Improving documentation.
*   Writing tests.
*   Identifying and fixing bugs.

Please fork the repository, make your changes, and submit a pull request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
