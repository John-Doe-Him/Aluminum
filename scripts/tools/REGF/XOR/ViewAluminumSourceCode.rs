
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;
use regex::Regex;
use serde_json;
use reqwest;
use tokio;

// Constants for browser-specific paths and commands
const CHROME_PATH: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
const FIREFOX_PATH: &str = r"C:\Program Files\Mozilla Firefox\firefox.exe";
const EDGE_PATH: &str = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";

// Function to retrieve Aluminum source code
async fn get_aluminum_source() -> Result<String, Box<dyn std::error::Error>> {
    // URL of the Aluminum source code repository
    let url = "";
    
    // Download the source code
    let response = reqwest::get(url).await?;
    let bytes = response.bytes().await?;
    
    // Save the zip file temporarily
    let temp_file = "aluminum_source.zip";
    fs::write(temp_file, &bytes)?;
    
    // Unzip the file
    let output = Command::new("powershell")
        .args(&["-command", &format!("Expand-Archive -Path {} -DestinationPath aluminum_source", temp_file)])
        .output()?;
    
    if !output.status.success() {
        return Err("Failed to unzip the source code".into());
    }
    
    // Read the source code
    let mut source = String::new();
    visit_dirs(Path::new("aluminum_source"), &mut |entry| {
        if let Some(ext) = entry.path().extension() {
            if ext == "rs" {
                let mut file = fs::File::open(entry.path())?;
                file.read_to_string(&mut source)?;
            }
        }
        Ok(())
    })?;
    
    // Clean up temporary files
    fs::remove_file(temp_file)?;
    fs::remove_dir_all("aluminum_source")?;
    
    Ok(source)
}

// Helper function to recursively visit directories
fn visit_dirs(dir: &Path, cb: &mut dyn FnMut(&fs::DirEntry) -> io::Result<()>) -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry)?;
            }
        }
    }
    Ok(())
}

// Function to detect the default browser
fn detect_default_browser() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("powershell")
        .args(&["-command", "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice | Select-Object -ExpandProperty ProgId"])
        .output()?;
    
    let browser = String::from_utf8(output.stdout)?.trim().to_lowercase();
    
    if browser.contains("chrome") {
        Ok("chrome".to_string())
    } else if browser.contains("firefox") {
        Ok("firefox".to_string())
    } else if browser.contains("edge") {
        Ok("edge".to_string())
    } else {
        Err("Unsupported default browser".into())
    }
}

// Function to get the browser version
fn get_browser_version(browser: &str) -> Result<String, Box<dyn std::error::Error>> {
    let (path, args) = match browser {
        "chrome" => (CHROME_PATH, vec!["--version"]),
        "firefox" => (FIREFOX_PATH, vec!["--version"]),
        "edge" => (EDGE_PATH, vec!["--version"]),
        _ => return Err("Unsupported browser".into()),
    };
    
    let output = Command::new(path)
        .args(&args)
        .output()?;
    
    let version = String::from_utf8(output.stdout)?;
    let re = Regex::new(r"\d+\.\d+\.\d+\.\d+")?;
    
    if let Some(cap) = re.captures(&version) {
        Ok(cap[0].to_string())
    } else {
        Err("Failed to extract version".into())
    }
}

// Function to compare Aluminum with the browser's source
fn compare_aluminum_with_browser(aluminum_source: &str, browser: &str, version: &str) -> Result<String, Box<dyn std::error::Error>> {
    // This is a placeholder function. In reality, this would be a complex process involving
    // downloading the browser's source code (if available), parsing both codebases,
    // and performing a detailed comparison.
    
    let comparison = format!(
        "Comparison between Aluminum and {} version {}:\n\n\
         1. Aluminum is written in Rust, while {} is primarily written in C++.\n\
         2. Aluminum is a lightweight browser, while {} is a full-featured browser.\n\
         3. Aluminum's codebase is significantly smaller than {}'s.\n\
         4. Aluminum focuses on privacy and security by default, while {} offers various privacy features that can be enabled.\n\
         5. Aluminum's rendering engine is custom-built, while {} uses {}.",
        browser, version, browser, browser, browser, browser, browser,
        match browser {
            "chrome" | "edge" => "Blink",
            "firefox" => "Gecko",
            _ => "an unknown engine",
        }
    );
    
    Ok(comparison)
}

// Main function to orchestrate the process
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Fetching Aluminum source code...");
    let aluminum_source = get_aluminum_source().await?;
    
    println!("Detecting default browser...");
    let default_browser = detect_default_browser()?;
    
    println!("Getting browser version...");
    let browser_version = get_browser_version(&default_browser)?;
    
    println!("Comparing Aluminum with the default browser...");
    let comparison = compare_aluminum_with_browser(&aluminum_source, &default_browser, &browser_version)?;
    
    // Create a JSON object with the results
    let result = serde_json::json!({
        "aluminum_source_length": aluminum_source.len(),
        "default_browser": default_browser,
        "browser_version": browser_version,
        "comparison": comparison,
    });
    
    // Write the result to a file
    fs::write("aluminum_comparison_result.json", serde_json::to_string_pretty(&result)?)?;
    
    println!("Analysis complete. Results saved to 'aluminum_comparison_result.json'");
    
    Ok(())
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_default_browser() {
        let result = detect_default_browser();
        assert!(result.is_ok());
        let browser = result.unwrap();
        assert!(vec!["chrome", "firefox", "edge"].contains(&browser.as_str()));
    }

    #[test]
    fn test_get_browser_version() {
        let browsers = vec!["chrome", "firefox", "edge"];
        for browser in browsers {
            let result = get_browser_version(browser);
            assert!(result.is_ok());
            let version = result.unwrap();
            assert!(Regex::new(r"\d+\.\d+\.\d+\.\d+").unwrap().is_match(&version));
        }
    }

    #[tokio::test]
    async fn test_get_aluminum_source() {
        let result = get_aluminum_source().await;
        assert!(result.is_ok());
        let source = result.unwrap();
        assert!(!source.is_empty());
        assert!(source.contains("fn main()"));
    }
}
