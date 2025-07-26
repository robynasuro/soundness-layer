use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bip39;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use indicatif::{ProgressBar, ProgressStyle};
use once_cell::sync::Lazy;
use pbkdf2::pbkdf2_hmac_array;
use rand::{rngs::OsRng, RngCore};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;
const ITERATIONS: u32 = 100_000;

static PASSWORD_CACHE: Lazy<Mutex<Option<(String, String)>>> = Lazy::new(|| Mutex::new(None));

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "https://testnet.soundness.xyz")]
    endpoint: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    GenerateKey {
        #[arg(short, long)]
        name: String,
    },
    ListKeys,
    Send {
        #[arg(short = 'p', long)]
        proof_file: PathBuf,
        #[arg(short = 'l', long)]
        elf_file: Option<PathBuf>,
        #[arg(short = 'k', long)]
        key_name: String,
        #[arg(short = 's', long)]
        proving_system: ProvingSystem,
        #[arg(short = 'd', long)]
        payload: Option<serde_json::Value>,
        #[arg(short = 'g', long, value_parser = clap::value_parser!(Game))]
        game: Option<Game>,
    },
    ImportPhrase {
        #[arg(short, long)]
        phrase: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ProvingSystem {
    Sp1,
    Ligetron,
    Risc0,
    Noir,
    Starknet,
    Miden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Game {
    EightQueens,
    TicTacToe,
}

impl FromStr for Game {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tic-tac-toe" | "tictactoe" => Ok(Game::TicTacToe),
            "8-queens" | "8queens" | "eight-queens" | "eightqueens" => Ok(Game::EightQueens),
            _ => Err(format!("Invalid game: {}. Valid games are: tic-tac-toe, tictactoe, 8-queens, 8queens, eight-queens, eightqueens", s)),
        }
    }
}

impl std::fmt::Display for Game {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Game::EightQueens => write!(f, "8queens"),
            Game::TicTacToe => write!(f, "tictactoe"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyPair {
    public_key: Vec<u8>,
    public_key_string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_secret_key: Option<EncryptedSecretKey>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedSecretKey {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    encrypted_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyStore {
    keys: HashMap<String, KeyPair>,
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    pbkdf2_hmac_array::<Sha256, KEY_LENGTH>(password.as_bytes(), salt, ITERATIONS)
}

fn encrypt_secret_key(secret_key: &[u8], password: &str) -> Result<EncryptedSecretKey, String> {
    let mut rng = OsRng;
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce = [0u8; NONCE_LENGTH];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let key_bytes = derive_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let encrypted_data = cipher
        .encrypt(Nonce::from_slice(&nonce), secret_key)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(EncryptedSecretKey {
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        encrypted_data,
    })
}

fn decrypt_secret_key(encrypted: &EncryptedSecretKey, password: &str) -> Result<Vec<u8>, String> {
    let key_bytes = derive_key(password, &encrypted.salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            encrypted.encrypted_data.as_slice(),
        )
        .map_err(|e| format!("Decryption failed: {}", e))
}

fn create_progress_bar(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(120));
    pb
}

fn load_key_store() -> Result<KeyStore, String> {
    let key_store_path = PathBuf::from("key_store.json");
    if key_store_path.exists() {
        let contents = fs::read_to_string(&key_store_path)
            .map_err(|e| format!("Failed to read key store: {}", e))?;
        let key_store: KeyStore = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse key store: {}", e))?;
        Ok(key_store)
    } else {
        Ok(KeyStore {
            keys: HashMap::new(),
        })
    }
}

fn save_key_store(key_store: &KeyStore) -> Result<(), String> {
    let key_store_path = PathBuf::from("key_store.json");
    let contents = serde_json::to_string_pretty(key_store)
        .map_err(|e| format!("Failed to serialize key store: {}", e))?;
    fs::write(key_store_path, contents)
        .map_err(|e| format!("Failed to write key store: {}", e))?;
    Ok(())
}

fn generate_key_pair(name: &str) -> Result<(), String> {
    let mut key_store = load_key_store().map_err(|e| format!("Failed to load key store: {}", e))?;

    if key_store.keys.contains_key(name) {
        return Err(format!("Key pair with name \"{}\" already exists", name));
    }

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let public_key_string = BASE64.encode(&public_key_bytes);

    let secret_key_bytes = signing_key.to_bytes();
    let mnemonic = bip39::Mnemonic::from_entropy(&secret_key_bytes)
        .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;
    let mnemonic_string = mnemonic.to_string();

    println!("\n📝 IMPORTANT: Save this mnemonic phrase securely!");
    println!("{}", mnemonic_string);
    println!("⚠️ WARNING: This is the only time you will see this mnemonic!");
    println!("⚠️ WARNING: You will need it to recover your secret key if the key store is lost!");

    let password = prompt_password("Enter password for secret key: ")
        .map_err(|e| format!("Failed to read password: {}", e))?;
    let confirm_password = prompt_password("Confirm password: ")
        .map_err(|e| format!("Failed to read confirm password: {}", e))?;

    if password != confirm_password {
        return Err("Passwords do not match".to_string());
    }

    let encrypted_secret = encrypt_secret_key(&secret_key_bytes, &password)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    key_store.keys.insert(
        name.to_string(),
        KeyPair {
            public_key: public_key_bytes.to_vec(),
            public_key_string: public_key_string.clone(),
            encrypted_secret_key: Some(encrypted_secret),
        },
    );

    save_key_store(&key_store).map_err(|e| format!("Failed to save key store: {}", e))?;
    println!("\n✅ Generated new key pair \"{}\"", name);
    println!("🔑 Public key: {}", public_key_string);
    Ok(())
}

fn import_phrase(phrase: &str, name: &str) -> Result<(), String> {
    let mut key_store = load_key_store().map_err(|e| format!("Failed to load key store: {}", e))?;

    if key_store.keys.contains_key(name) {
        return Err(format!("Key pair with name \"{}\" already exists", name));
    }

    let mnemonic = bip39::Mnemonic::from_str(phrase)
        .map_err(|e| format!("Invalid seed phrase: {}", e))?;
    let entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        return Err("Invalid entropy length for mnemonic (expected 32 bytes)".to_string());
    }

    let secret_key_bytes: [u8; 32] = entropy[..32]
        .try_into()
        .map_err(|_| "Invalid secret key length".to_string())?;
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let public_key_string = BASE64.encode(&public_key_bytes);

    println!("\n📝 Importing key pair \"{}\"", name);
    let password = prompt_password("Enter password for secret key: ")
        .map_err(|e| format!("Failed to read password: {}", e))?;
    let confirm_password = prompt_password("Confirm password: ")
        .map_err(|e| format!("Failed to read confirm password: {}", e))?;

    if password != confirm_password {
        return Err("Passwords do not match".to_string());
    }

    let encrypted_secret = encrypt_secret_key(&secret_key_bytes, &password)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    key_store.keys.insert(
        name.to_string(),
        KeyPair {
            public_key: public_key_bytes.to_vec(),
            public_key_string: public_key_string.clone(),
            encrypted_secret_key: Some(encrypted_secret),
        },
    );

    save_key_store(&key_store).map_err(|e| format!("Failed to save key store: {}", e))?;
    println!("\n✅ Imported key pair \"{}\"", name);
    println!("🔑 Public key: {}", public_key_string);
    Ok(())
}

fn prompt_menu() -> Result<(), String> {
    let mut name = String::new();
    loop {
        println!("\n🔐 Key Management Setup");
        print!("Enter key name (e.g., mykey): ");
        io::stdout().flush().map_err(|e| format!("Failed to flush stdout: {}", e))?;

        name.clear();
        io::stdin()
            .read_line(&mut name)
            .map_err(|e| format!("Failed to read key name: {}", e))?;
        name = name.trim().to_string();

        if name.is_empty() {
            eprintln!("Error: Key name cannot be empty");
            continue;
        }

        let key_store = load_key_store().map_err(|e| format!("Failed to load key store: {}", e))?;
        if key_store.keys.contains_key(&name) {
            eprintln!("Error: Key pair with name \"{}\" already exists", name);
            continue;
        }
        break;
    }

    println!("\n🔐 Key Management Menu for \"{}\":", name);
    println!("1. Import a 24-word BIP-39 mnemonic phrase");
    println!("2. Generate a new key pair");
    print!("Enter choice (1 or 2): ");
    io::stdout().flush().map_err(|e| format!("Failed to flush stdout: {}", e))?;

    let mut choice = String::new();
    io::stdin()
        .read_line(&mut choice)
        .map_err(|e| format!("Failed to read input: {}", e))?;
    let choice = choice.trim();

    match choice {
        "1" => {
            print!("\nEnter your 24-word BIP-39 mnemonic phrase: ");
            io::stdout().flush().map_err(|e| format!("Failed to flush stdout: {}", e))?;
            let mut phrase = String::new();
            io::stdin()
                .read_line(&mut phrase)
                .map_err(|e| format!("Failed to read mnemonic phrase: {}", e))?;
            let phrase = phrase.trim();
            import_phrase(phrase, &name)
        }
        "2" => generate_key_pair(&name),
        _ => Err("Invalid choice. Please enter 1 or 2.".to_string()),
    }
}

fn list_keys() -> Result<(), String> {
    let key_store = load_key_store().map_err(|e| format!("Failed to load key store: {}", e))?;

    if key_store.keys.is_empty() {
        println!("No key pairs found. Generate one with \"generate-key\" command.");
        return Ok(());
    }

    println!("Available key pairs:");
    for (name, key_pair) in key_store.keys {
        println!("- {} (Public key: {})", name, key_pair.public_key_string);
    }
    Ok(())
}

fn calculate_key_store_hash(key_store: &KeyStore) -> String {
    let serialized = serde_json::to_string(key_store).unwrap_or_default();
    format!("{:x}", Sha256::digest(serialized.as_bytes()))
}

fn sign_payload(payload: &[u8], key_name: &str) -> Result<Vec<u8>, String> {
    let key_store = load_key_store().map_err(|e| format!("Failed to load key store: {}", e))?;
    let key_store_hash = calculate_key_store_hash(&key_store);

    let key_pair = key_store
        .keys
        .get(key_name)
        .ok_or_else(|| format!("Key pair \"{}\" not found", key_name))?;

    let encrypted_secret = key_pair
        .encrypted_secret_key
        .as_ref()
        .ok_or_else(|| format!("Secret key not found for \"{}\"", key_name))?;

    let password = {
        let mut password_guard = PASSWORD_CACHE.lock().unwrap();

        if let Some((stored_password, stored_hash)) = password_guard.as_ref() {
            if stored_hash != &key_store_hash {
                *password_guard = None;
                drop(password_guard);
                return sign_payload(payload, key_name);
            }
            stored_password.clone()
        } else {
            let new_password = prompt_password("Enter password to decrypt the secret key: ")
                .map_err(|e| format!("Failed to read password: {}", e))?;

            if let Err(e) = decrypt_secret_key(encrypted_secret, &new_password) {
                return Err(format!("Invalid password: {}", e));
            }

            *password_guard = Some((new_password.clone(), key_store_hash));
            new_password
        }
    };

    let pb = create_progress_bar("✍️ Signing payload...");

    let secret_key_bytes = decrypt_secret_key(encrypted_secret, &password)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    let secret_key_array: [u8; 32] = secret_key_bytes
        .try_into()
        .map_err(|_| "Invalid secret key length".to_string())?;

    let signing_key = SigningKey::from_bytes(&secret_key_array);
    let signature = signing_key.sign(payload);
    pb.finish_with_message("✍️ Payload signed successfully");

    Ok(signature.to_bytes().to_vec())
}

fn get_public_key(key_name: &str) -> Result<Vec<u8>, String> {
    let key_store = load_key_store().map_err(|e| format!("Failed to load key store: {}", e))?;
    let key_pair = key_store
        .keys
        .get(key_name)
        .ok_or_else(|| format!("Key pair \"{}\" not found", key_name))?;
    Ok(key_pair.public_key.clone())
}

fn is_blob_id(input: &str) -> bool {
    if input.contains('/') || input.contains('\\') {
        return false;
    }
    input.len() > 20
        && input.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
        })
}

#[derive(Debug, Deserialize)]
struct ServerResponse {
    status: String,
    message: String,
    proving_system: String,
    proof_verification_status: Option<bool>,
    sui_status: Option<String>,
    sui_transaction_digest: Option<String>,
    proof_data_blob_id: Option<String>,
    vk_blob_id: Option<String>,
    suiscan_link: Option<String>,
    walruscan_links: Option<Vec<String>>,
}

fn format_server_response(response: &ServerResponse) {
    println!("\n🎯 Proof Submission Results");
    println!("═══════════════════════════");

    let (icon, text) = if response.status == "success" {
        ("✅", response.status.to_uppercase())
    } else {
        ("❌", response.status.to_uppercase())
    };
    println!("{} Status: {}", icon, text);
    println!("📝 Message: {}", response.message);
    println!("🔧 Proving System: {}", response.proving_system);

    if let Some(verification_status) = response.proof_verification_status {
        let (icon, text) = if verification_status {
            ("✅", "SUCCESS")
        } else {
            ("❌", "FAILED")
        };
        println!("🔍 Proof Verification: {} {}", icon, text);
    }

    if let Some(sui_status) = &response.sui_status {
        let sui_icon = if sui_status == "success" {
            "✅"
        } else {
            "❌"
        };
        println!(
            "⛓️ Sui Transaction: {} {}",
            sui_icon,
            sui_status.to_uppercase()
        );
    }

    if let Some(digest) = &response.sui_transaction_digest {
        println!("🔗 Transaction Digest: {}", digest);
    }

    if let Some(proof_blob_id) = &response.proof_data_blob_id {
        println!("📦 Proof Blob ID: {}", proof_blob_id);
    }

    if let Some(vk_blob_id) = &response.vk_blob_id {
        println!("🔑 Program Blob ID: {}", vk_blob_id);
    }

    if let Some(suiscan_link) = &response.suiscan_link {
        println!("🔍 Suiscan Link: {}", suiscan_link);
    }

    if let Some(walruscan_links) = &response.walruscan_links {
        if walruscan_links.len() >= 2 {
            println!("🌊 Walruscan Links:");
            println!("   📦 Proof Data: {}", walruscan_links[0]);
            println!("   🔑 VK: {}", walruscan_links[1]);
        }
    }

    println!("═══════════════════════════");
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = Args::parse();
    let client = reqwest::Client::new();

    match args.command {
        Commands::GenerateKey { name } => {
            generate_key_pair(&name)?;
        }
        Commands::ListKeys => {
            list_keys()?;
        }
        Commands::Send {
            proof_file,
            elf_file,
            key_name,
            proving_system,
            payload,
            game,
        } => {
            if game.is_none() && elf_file.is_none() {
                return Err("Error: When no game flag is provided, an ELF file (-l/--elf-file) must be specified.\n\nUsage:\n  - With game: soundness-cli send -p proof.bin -g tic-tac-toe -k my_key\n  - With ELF: soundness-cli send -p proof.bin -l program.elf -k my_key".to_string());
            }

            let proof_input = proof_file.to_string_lossy().to_string();
            let proof_is_blob = is_blob_id(&proof_input);

            let (elf_input, elf_is_blob) = if let Some(ref elf_path) = elf_file {
                let elf_input = elf_path.to_string_lossy().to_string();
                let elf_is_blob = is_blob_id(&elf_input);
                (Some(elf_input), elf_is_blob)
            } else {
                (None, false)
            };

            println!("🔍 Analyzing inputs...");
            if proof_is_blob {
                println!("📁 Proof: Detected as Walrus Blob ID: {}", proof_input);
            } else {
                println!("📁 Proof: Detected as file path: {}", proof_input);
            }

            match &elf_input {
                Some(elf_str) => {
                    if elf_is_blob {
                        println!("📁 ELF Program: Detected as Walrus Blob ID: {}", elf_str);
                    } else {
                        println!("📁 ELF Program: Detected as file path: {}", elf_str);
                    }
                }
                None => {
                    println!("📁 ELF Program: Not provided (using game mode)");
                }
            }

            let reading_pb = create_progress_bar("📂 Processing inputs...");

            let (proof_content, proof_blob_id, proof_filename) = if proof_is_blob {
                (None, Some(proof_input.clone()), "proof.bin".to_string())
            } else {
                let content = fs::read(&proof_file).map_err(|e| {
                    format!("Failed to read proof file: {}: {}", proof_file.display(), e)
                })?;
                let filename = proof_file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                (Some(BASE64.encode(&content)), None, filename)
            };

            let (elf_content, elf_blob_id, elf_filename) = match (&elf_input, &elf_file) {
                (Some(elf_str), Some(elf_path)) => {
                    if elf_is_blob {
                        (None, Some(elf_str.clone()), "program.elf".to_string())
                    } else {
                        let content = fs::read(elf_path).map_err(|e| {
                            format!("Failed to read ELF file: {}: {}", elf_path.display(), e)
                        })?;
                        let filename = elf_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        (Some(BASE64.encode(&content)), None, filename)
                    }
                }
                _ => (None, None, "".to_string()),
            };

            reading_pb.finish_with_message("📂 Inputs processed successfully");

            let mut request_body = serde_json::json!({
                "proof_filename": proof_filename,
                "proving_system": format!("{:?}", proving_system).to_lowercase(),
                "payload": payload.unwrap_or_default(),
                "game": game.unwrap_or(Game::EightQueens).to_string(),
            });

            if let Some(content) = proof_content {
                request_body["proof"] = serde_json::Value::String(content.clone());
            } else if let Some(blob_id) = proof_blob_id {
                request_body["proof_blob_id"] = serde_json::Value::String(blob_id);
            }

            if !elf_filename.is_empty() {
                request_body["elf_filename"] = serde_json::Value::String(elf_filename.clone());

                if let Some(content) = elf_content {
                    request_body["elf"] = serde_json::Value::String(content.clone());
                } else if let Some(blob_id) = elf_blob_id {
                    request_body["elf_blob_id"] = serde_json::Value::String(blob_id);
                }
            }

            let proof_value = request_body
                .get("proof")
                .or_else(|| request_body.get("proof_blob_id"))
                .unwrap_or(&serde_json::Value::Null)
                .as_str()
                .unwrap_or("");

            let elf_value = request_body
                .get("elf")
                .or_else(|| request_body.get("elf_blob_id"))
                .unwrap_or(&serde_json::Value::Null)
                .as_str()
                .unwrap_or("");

            let canonical_string = if !elf_filename.is_empty() {
                format!(
                    "proof:{}\nelf:{}\nproof_filename:{}\nelf_filename:{}\nproving_system:{}",
                    proof_value,
                    elf_value,
                    proof_filename,
                    elf_filename,
                    format!("{:?}", proving_system).to_lowercase()
                )
            } else {
                format!(
                    "proof:{}\nproof_filename:{}\nproving_system:{}",
                    proof_value,
                    proof_filename,
                    format!("{:?}", proving_system).to_lowercase()
                )
            };

            request_body["canonical_string"] = serde_json::Value::String(canonical_string.clone());

            let signature = sign_payload(canonical_string.as_bytes(), &key_name)
                .map_err(|e| format!("Failed to sign payload: {}", e))?;
            let public_key = get_public_key(&key_name)
                .map_err(|e| format!("Failed to get public key: {}", e))?;

            let sending_pb = create_progress_bar("🚀 Sending to server...");
            let response = client
                .post(format!("{}/api/proof", args.endpoint))
                .header("Content-Type", "application/json")
                .header("X-Signature", BASE64.encode(&signature))
                .header("X-Public-Key", BASE64.encode(&public_key))
                .json(&request_body)
                .send()
                .await
                .map_err(|e| format!("Failed to send request to {}: {}", args.endpoint, e))?;

            sending_pb.finish_with_message("🚀 Request sent successfully");

            if response.status().is_success() {
                println!("\n✅ Successfully sent files to {}", args.endpoint);
                let response_text = response
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;

                match serde_json::from_str::<ServerResponse>(&response_text) {
                    Ok(parsed_response) => {
                        format_server_response(&parsed_response);
                    }
                    Err(_) => {
                        println!("📄 Raw server response:");
                        println!("{}", response_text);
                    }
                }
            } else {
                println!("\n❌ Error: Server returned status {}", response.status());
                let error_text = response
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read error response: {}", e))?;
                println!("Error details: {}", error_text);
            }
        }
        Commands::ImportPhrase { phrase } => {
            if let Some(phrase) = phrase {
                let mut name = String::new();
                loop {
                    print!("Enter key name (e.g., mykey): ");
                    io::stdout().flush().map_err(|e| format!("Failed to flush stdout: {}", e))?;

                    name.clear();
                    io::stdin()
                        .read_line(&mut name)
                        .map_err(|e| format!("Failed to read key name: {}", e))?;
                    name = name.trim().to_string();

                    if name.is_empty() {
                        eprintln!("Error: Key name cannot be empty");
                        continue;
                    }

                    let key_store = load_key_store().map_err(|e| format!("Failed to load key store: {}", e))?;
                    if key_store.keys.contains_key(&name) {
                        eprintln!("Error: Key pair with name \"{}\" already exists", name);
                        continue;
                    }
                    break;
                }

                import_phrase(&phrase, &name)?;
            } else {
                prompt_menu()?;
            }
        }
    }

    Ok(())
}
