# Soundness CLI (robynasuro Fork)
A command-line interface (CLI) tool for interacting with the Soundness Layer testnet, a platform for submitting zero-knowledge proofs for games like 8 Queens. This fork adds support for importing 24-word BIP-39 mnemonic phrases, fixes key store overwrite issues, and improves logging.

## Features
**Generate Key Pair**: Create an Ed25519 key pair with a 24-word BIP-39 mnemonic phrase.
**Import Mnemonic Phrase**: Import a 24-word BIP-39 mnemonic to create a key pair (new in this fork).
**List Keys**: Display all stored key pairs with their public keys.
**Send Proof**: Submit zero-knowledge proofs to the testnet server using Ligetron, SP1, or RISC0 proving systems.
**Secure Key Storage**: Store encrypted secret keys in key_store.json with password protection.
**Improved Logging**: Enhanced debug logs for key store operations (new in this fork).

### Installation
Prerequisites
**Rust**: Install the Rust toolchain via rustup.rs (stable, latest recommended).
**Cargo**: Included with Rust.
**Git**: For cloning the repository.

# Steps
1. **Install Rust** (if not already installed):
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

then choose ``1) Proceed with standard installation (default - just press enter)``

Verify Rust installation:
```
rustc --version
cargo --version
```


2. Clone the repository:
```
git clone https://github.com/robynasuro/soundness-layer.git
cd soundess-layer/soundness-cli
```

3. Build and install the CLI:
```
cargo build --release
cargo install --path .
```

4. Verify installation:
```
soundness-cli --help
```

# Testnet Instructions
To use this CLI with the Soundness Layer testnet , follow these steps to set up and play ZK games.

## Step 1: Get Access

To join the testnet, you'll need either the `Onboarded` role from our Discord or a special invite code.

1.  **Join our Discord:** Hop into the [Soundness Labs Discord](https://discord.gg/SoundnessLabs) and get the `Onboarded` role to participate.
2.  **Follow us on X:** Keep an eye on our [X account](https://x.com/SoundnessLabs). We regularly post invite codes for our community.

## Step 2: Prepare Your Key
1.  **If you have the `Onboarded role`**: Use your existing key from onboarding. Skip to Step 3.
2.  **If you have an invite code**: Generate or import a key pair.

# Generate a Key Pair
```
soundness-cli generate-key --name your-key-name
```

* Outputs a 24-word mnemonic phrase (save securely offline).
* Prompts for a password to encrypt the secret key.
* Stores the key in `key_store.json`.

## Example:
```
soundness-cli generate-key --name testkey
```

## Output:
```
✅ Generated new key pair 'testkey'
🔑 Public key: YXbQJjrbhaCxhbSjiVytAeclQ5o3I2KugOkl4s5i8pg=
```

## Import a Mnemonic Phrase

If you have a 24-word BIP-39 mnemonic, import it:

```soundness-cli import-phrase --phrase "your-phrase" --name your-key-name```

* Prompts for a password to encrypt the secret key.
* Stores the key in `key_store.json`.

## Example:
```soundness-cli import-phrase --phrase "your-phrase" --name testkey```

# Step 3: Play a Game and Send Your Proof

After winning a game (e.g., 8 Queens), submit your proof to the testnet.

```soundness-cli send --proof-file <proof-blob-id> --game <game-name> --key-name your-key-name --proving-system ligetron --payload '<json-payload>'```

**Command Breakdown:**

* `--proof-file` (`-p`): The unique Walrus Blob ID for your proof, which you receive after winning a game.
* `--game` (`-g`): The name of the game you played (e.g., `8queens` or `tictactoe`).
* `--key-name` (`-k`): The name you chose for your key in Step 2.
* `--proving-system` (`-s`): The ZK proving system. For our current testnet games, this is `ligetron`.
* `--payload` (`-d`): A JSON string with the specific inputs required to verify your Ligetron proof.

## Alternative: Send Proofs with Local Files or Mixed Inputs

Local Files:

```soundness-cli send --proof-file path/to/proof.proof --elf-file path/to/program.elf --key-name testkey --proving-system ligetron```

Mixed:

```soundness-cli send --proof-file path/to/proof.proof --elf-file <walrus-blob-id> --key-name testkey --proving-system ligetron```
```
