#!/bin/bash

# Soundness CLI One-Step Setup Script
# Installs dependencies, Rust, clones the repo, builds the CLI, runs soundness-cli import-phrase,
# and guides user to the correct directory
# Designed to work on a fresh VPS (e.g., Ubuntu 22.04/24.04) or GitHub Codespaces

set -e  # Exit on error

echo "🚖 Starting Soundness CLI one-step setup..."

# Step 1: Install basic dependencies (git, curl, build-essential)
if ! command -v git &> /dev/null || ! command -v curl &> /dev/null; then
    echo "📦 Installing basic dependencies (git, curl, build-essential)..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y git curl build-essential
    else
        echo "❌ Error: This script supports Ubuntu/Debian-based systems. Please install git, curl, and build-essential manually."
        exit 1
    fi
else
    echo "✅ Basic dependencies already installed"
fi

# Step 2: Install Rust and ensure PATH is set (skip if already installed)
if ! command -v rustc &> /dev/null || ! command -v cargo &> /dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "✅ Rust already installed"
    rustc --version
    cargo --version
fi
# Ensure ~/.cargo/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.cargo/bin:"* ]]; then
    echo "📝 Adding ~/.cargo/bin to PATH..."
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Step 3: Clone the repository (skip if already in soundness-layer)
if [ ! -d ".git" ] || ! git remote -v | grep -q "robynasuro/soundness-layer"; then
    echo "📂 Cloning robynasuro/soundness-layer repository..."
    rm -rf soundness-layer  # Clean up any existing directory
    git clone https://github.com/robynasuro/soundness-layer.git
    cd soundness-layer
else
    echo "✅ Already in soundness-layer repository"
fi

# Step 4: Navigate to soundness-cli and build
echo "🛠️ Building Soundness CLI..."
cd soundness-cli
cargo build --release
cargo install --path .

# Step 5: Verify installation
echo "🔍 Verifying Soundness CLI installation..."
if command -v soundness-cli &> /dev/null; then
    echo "✅ Soundness CLI installed successfully"
    soundness-cli --version
else
    echo "❌ Failed to install Soundness CLI. Ensure ~/.cargo/bin is in your PATH."
    echo "👉 Run the following commands to fix PATH:"
    echo "echo 'export PATH=\"\$HOME/.cargo/bin:\$PATH\"' >> ~/.bashrc"
    echo "source ~/.bashrc"
    exit 1
fi

# Step 6: Run soundness-cli import-phrase with redirected stdin
echo "🔐 Running soundness-cli import-phrase..."
soundness-cli import-phrase < /dev/tty

echo "🎉 Setup complete! Key pair created, ready to use Soundness CLI."
echo "📂 You are now in the project directory: $(pwd)"
echo "🔑 Your key pair is stored in key_store.json. Back it up securely!"
echo "👉 To use Soundness CLI, run commands like: soundness-cli --help"
