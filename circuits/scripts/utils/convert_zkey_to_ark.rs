#!/usr/bin/env -S cargo +stable -Zscript
//! ```cargo
//! [dependencies]
//! ark-circom = "0.1.0"
//! ark-serialize = "0.4.0"
//! ark-bn254 = "0.4.0"
//! color-eyre = "0.6"
//! ```

//! Convert .zkey to .ark format using ark-circom
//!
//! Usage:
//!   cargo +nightly -Zscript convert_zkey_to_ark.rs keys/disclosure_pk.zkey keys/disclosure_pk.ark

use ark_circom::read_zkey;
use ark_serialize::CanonicalSerialize;
use color_eyre::Result;
use std::env;
use std::fs::File;
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 3 {
        eprintln!("Usage: {} <input.zkey> <output.ark>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  cargo +nightly -Zscript convert_zkey_to_ark.rs keys/disclosure_pk.zkey keys/disclosure_pk.ark");
        std::process::exit(1);
    }
    
    let zkey_path = Path::new(&args[1]);
    let ark_path = Path::new(&args[2]);
    
    if !zkey_path.exists() {
        eprintln!("Error: File not found: {}", zkey_path.display());
        std::process::exit(1);
    }
    
    println!("Reading .zkey file: {}", zkey_path.display());
    let mut file = File::open(zkey_path)?;
    let (params, _matrices) = read_zkey(&mut file)?;
    
    println!("Writing .ark file: {}", ark_path.display());
    let mut output = File::create(ark_path)?;
    params.serialize_compressed(&mut output)?;
    
    println!("✓ Conversion successful!");
    
    // Show file sizes
    let zkey_size = std::fs::metadata(zkey_path)?.len();
    let ark_size = std::fs::metadata(ark_path)?.len();
    println!("\nFile sizes:");
    println!("  Original .zkey: {} bytes", zkey_size);
    println!("  Arkworks .ark:  {} bytes", ark_size);
    
    Ok(())
}
