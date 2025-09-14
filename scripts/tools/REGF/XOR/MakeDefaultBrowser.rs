use std::process::Command;
use std::io::{self, Write};
use std::path::Path;
use std::fs::{self, File};
use std::time::{Duration, Instant};
use winreg::enums::*;
use winreg::RegKey;

// Constants for registry paths and values
const HKCU_CLASSES_ROOT: &str = r"HKEY_CURRENT_USER\Software\Classes";
const ALUMINUM_PROG_ID: &str = "AluminumHTML";
const ALUMINUM_EXE_PATH: &str = r"C:\Program Files\Aluminum\aluminum.exe";
const FILE_ASSOCIATIONS: [&str; 4] = [".htm", ".html", ".shtml", ".xht"];
const PROTOCOL_ASSOCIATIONS: [&str; 3] = ["http", "https", "ftp"];

/// Makes Aluminum the default browser by modifying Windows Registry settings
fn make_aluminum_default_browser() -> io::Result<()> {
    println!("Starting the process to make Aluminum the default browser...");
    
    // Step 1: Create ProgID for Aluminum
    create_aluminum_prog_id()?;
    
    // Step 2: Associate file extensions with Aluminum
    associate_file_extensions()?;
    
    // Step 3: Associate protocols with Aluminum
    associate_protocols()?;
    
    // Step 4: Set Aluminum as the default browser in Windows Settings
    set_default_browser()?;
    
    // Step 5: Refresh system settings
    refresh_system_settings()?;
    
    println!("Aluminum has been successfully set as the default browser!");
    Ok(())
}

/// Creates the ProgID for Aluminum in the Windows Registry
fn create_aluminum_prog_id() -> io::Result<()> {
    println!("Creating ProgID for Aluminum...");
    
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes_key = hkcu.open_subkey_with_flags("Software\\Classes", KEY_ALL_ACCESS)?;
    
    // Create AluminumHTML ProgID
    let (aluminum_key, _) = classes_key.create_subkey(ALUMINUM_PROG_ID)?;
    aluminum_key.set_value("", &"Aluminum HTML Document")?;
    
    // Create default icon
    let (icon_key, _) = aluminum_key.create_subkey("DefaultIcon")?;
    icon_key.set_value("", &format!("{},0", ALUMINUM_EXE_PATH))?;
    
    // Create shell open command
    let (shell_key, _) = aluminum_key.create_subkey("shell\\open\\command")?;
    shell_key.set_value("", &format!("\"{}\" \"%1\"", ALUMINUM_EXE_PATH))?;
    
    println!("ProgID created successfully.");
    Ok(())
}

/// Associates file extensions with Aluminum
fn associate_file_extensions() -> io::Result<()> {
    println!("Associating file extensions with Aluminum...");
    
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes_key = hkcu.open_subkey_with_flags("Software\\Classes", KEY_ALL_ACCESS)?;
    
    for ext in FILE_ASSOCIATIONS.iter() {
        println!("  Associating {}...", ext);
        let (ext_key, _) = classes_key.create_subkey(ext)?;
        ext_key.set_value("", &ALUMINUM_PROG_ID)?;
        
        // Create OpenWithProgIds subkey
        let (open_with_key, _) = ext_key.create_subkey("OpenWithProgIds")?;
        open_with_key.set_value(ALUMINUM_PROG_ID, &Vec::<u8>::new())?;
    }
    
    println!("File extensions associated successfully.");
    Ok(())
}

/// Associates protocols with Aluminum
fn associate_protocols() -> io::Result<()> {
    println!("Associating protocols with Aluminum...");
    
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes_key = hkcu.open_subkey_with_flags("Software\\Classes", KEY_ALL_ACCESS)?;
    
    for protocol in PROTOCOL_ASSOCIATIONS.iter() {
        println!("  Associating {}...", protocol);
        let (protocol_key, _) = classes_key.create_subkey(protocol)?;
        protocol_key.set_value("", &format!("URL:{} Protocol", protocol))?;
        protocol_key.set_value("URL Protocol", &"")?;
        
        // Create default icon
        let (icon_key, _) = protocol_key.create_subkey("DefaultIcon")?;
        icon_key.set_value("", &format!("{},0", ALUMINUM_EXE_PATH))?;
        
        // Create shell open command
        let (shell_key, _) = protocol_key.create_subkey("shell\\open\\command")?;
        shell_key.set_value("", &format!("\"{}\" \"%1\"", ALUMINUM_EXE_PATH))?;
    }
    
    println!("Protocols associated successfully.");
    Ok(())
}

/// Sets Aluminum as the default browser in Windows Settings
fn set_default_browser() -> io::Result<()> {
    println!("Setting Aluminum as the default browser in Windows Settings...");
    
    // This step typically requires user interaction or elevated privileges
    // We'll simulate this by showing a message to the user
    println!("Please follow these steps to complete the process:");
    println!("1. Open Windows Settings");
    println!("2. Go to 'Apps' > 'Default apps'");
    println!("3. Scroll down and click on 'Web browser'");
    println!("4. Select 'Aluminum' from the list of available browsers");
    
    // Pause for user acknowledgment
    print!("Press Enter when you have completed these steps...");
    io::stdout().flush()?;
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    
    println!("Thank you for manually setting Aluminum as the default browser.");
    Ok(())
}

/// Refreshes system settings to apply changes
fn refresh_system_settings() -> io::Result<()> {
    println!("Refreshing system settings...");
    
    // Broadcast WM_SETTINGCHANGE message
    Command::new("rundll32")
        .args(&["user32.dll,UpdatePerUserSystemParameters"])
        .output()?;
    
    // Wait for changes to take effect
    let wait_time = Duration::from_secs(5);
    let start = Instant::now();
    print!("Waiting for changes to take effect");
    while start.elapsed() < wait_time {
        print!(".");
        io::stdout().flush()?;
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("\nSystem settings refreshed.");
    
    Ok(())
}

/// Main function to execute the default browser change
fn main() -> io::Result<()> {
    println!("Welcome to the Aluminum Default Browser Setup Utility");
    println!("====================================================");
    println!("This utility will set Aluminum as your default web browser.");
    println!("Please ensure you have administrative privileges before proceeding.");
    println!();
    
    print!("Do you want to continue? (y/n): ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    if input.trim().to_lowercase() == "y" {
        make_aluminum_default_browser()?;
        println!("====================================================");
        println!("Aluminum has been successfully set as your default browser!");
        println!("Thank you for choosing Aluminum. Happy browsing!");
    } else {
        println!("Operation cancelled. Aluminum was not set as the default browser.");
    }
    
    // Wait for user to read the final message
    print!("Press Enter to exit...");
    io::stdout().flush()?;
    io::stdin().read_line(&mut String::new())?;
    
    Ok(())
}
