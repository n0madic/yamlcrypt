use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine};
use block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit};
use cipher::generic_array::GenericArray;
use clap::{ArgMatches, Command};
use md5;
use rand::RngCore;
use serde_yaml::Value;
use std::env;

const CRYPT_PREFIX: &str = "CRYPT#";

fn parse_args() -> ArgMatches {
    let args: Vec<String> = env::args().map(|arg| {
        if arg.starts_with("-") && !arg.starts_with("--") && arg.len() > 2 {
            format!("--{}", &arg[1..])
        } else {
            arg
        }
    }).collect();

    Command::new("yamlcrypt")
        .about("Utility to encrypt/decrypt YAML values")
        .arg(clap::arg!(-e --encrypt "Encrypt values"))
        .arg(clap::arg!(-k --key <KEY> "The key in YAML for encryption").default_value("secrets"))
        .arg(clap::arg!(-p --password <PASSWORD> "Password for encryption"))
        .arg(clap::arg!(<FILE> "Input YAML file"))
        .get_matches_from(args)
}

fn main() -> Result<()> {
    let matches = parse_args();

    let encrypt = matches.get_flag("encrypt");
    let dict_key = matches.get_one::<String>("key").unwrap();
    let password = matches.get_one::<String>("password");
    let file = matches.get_one::<String>("FILE").unwrap();

    let password = password
        .map(|s| s.to_owned())
        .or_else(|| env::var("YAML_PASSWORD").ok())
        .context("Password must be provided via --password or YAML_PASSWORD")?;

    let md5_key = md5::compute(password.as_bytes());

    let content = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read file: {}", file))?;
    let mut data: Value = serde_yaml::from_str(&content).context("Failed to parse YAML")?;

    process_secrets(&mut data, dict_key, encrypt, md5_key.into())?;

    let yaml = serde_yaml::to_string(&data).context("Failed to serialize YAML")?;
    println!("---\n{yaml}");
    Ok(())
}

fn process_secrets(
    data: &mut Value,
    dict_key: &str,
    encrypt: bool,
    key: [u8; 16],
) -> Result<()> {
    let Some(secrets) = data.get_mut(dict_key) else { return Ok(()) };
    let Some(mapping) = secrets.as_mapping_mut() else { return Ok(()) };

    for (_k, v) in mapping.iter_mut() {
        let Some(s) = v.as_str() else { continue };

        let processed = if encrypt {
            if !s.starts_with(CRYPT_PREFIX) {
                let ciphertext = aes_cbc_encrypt(s, &key)?;
                format!("{CRYPT_PREFIX}{ciphertext}")
            } else {
                s.to_string()
            }
        } else {
            let clean = s.strip_prefix(CRYPT_PREFIX).unwrap_or(s);
            aes_cbc_decrypt(clean, &key)?
        };

        *v = Value::String(processed);
    }

    Ok(())
}

fn aes_cbc_encrypt(plaintext: &str, key: &[u8; 16]) -> Result<String> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let key = GenericArray::from_slice(key);
    let iv_arr = GenericArray::from_slice(&iv);

    let cipher = cbc::Encryptor::<aes::Aes128>::new(key, iv_arr);

    let block_size = aes::Aes128::block_size();
    let mut buffer = plaintext.as_bytes().to_vec();
    let needed_len = (buffer.len() / block_size + 1) * block_size;
    buffer.resize(needed_len, 0);

    let encrypted_len = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?.len();

    buffer.truncate(encrypted_len);

    let mut output = iv.to_vec();
    output.extend(buffer);
    Ok(general_purpose::STANDARD.encode(output))
}

fn aes_cbc_decrypt(ciphertext: &str, key: &[u8; 16]) -> Result<String> {
    let data = general_purpose::STANDARD.decode(ciphertext)?;
    if data.len() < 16 || (data.len() - 16) % aes::Aes128::block_size() != 0 {
        anyhow::bail!("Invalid ciphertext length");
    }

    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(&data[..16]);
    let ciphertext = &data[16..];

    let cipher = cbc::Decryptor::<aes::Aes128>::new(key, iv);
    let mut buffer = ciphertext.to_vec();

    cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

    let pad_len = *buffer.last().unwrap() as usize;
    if pad_len > buffer.len() {
        anyhow::bail!("Invalid padding");
    }
    buffer.truncate(buffer.len() - pad_len);

    String::from_utf8(buffer).context("Invalid UTF-8 in decrypted text")
}