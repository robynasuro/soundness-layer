#!/bin/bash

# Soundness CLI One-Step Setup Script
# Installs Rust, clones the repo, builds the CLI, and runs soundness-cli import-phrase

set -e  # Exit on error

echo "🚀 Starting Soundness CLI one-step setup..."

# Step 1: Install Rust (skip if already installed)
if ! command -v rustc &> /dev/null || ! command -v cargo &> /dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "✅ Rust already installed"
    rustc --version
    cargo --version
fi

# Step 2: Clone the repository (skip if already in soundness-layer)
if [ ! -d ".git" ] || ! git remote -v | grep -q "robynasuro/soundness-layer"; then
    echo "📂 Cloning robynasuro/soundness-layer repository..."
    rm -rf soundness-layer  # Clean up any existing directory
    git clone https://github.com/robynasuro/soundness-layer.git
    cd soundness-layer
else
    echo "✅ Already in soundness-layer repository"
fi

# Step 3: Navigate to soundness-cli and build
echo "🛠️ Building Soundness CLI..."
cd soundness-cli
cargo build --release
cargo install --path .

# Step 4: Verify installation
echo "🔍 Verifying Soundness CLI installation..."
if command -v soundness-cli &> /dev/null; then
    echo "✅ Soundness CLI installed successfully"
    soundness-cli --version
else
    echo "❌ Failed to install Soundness CLI"
    exit 1
fi

# Step 5: Run soundness-cli import-phrase
echo "🔐 Running soundness-cli import-phrase..."
soundness-cli import-phrase

# Clean up key_store.json
echo "🧹 Cleaning up key_store.json..."
rm -f soundness-cli/key_store.json

echo "🎉 Setup complete! Key pair created, ready to use Soundness CLI."
