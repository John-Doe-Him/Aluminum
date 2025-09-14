// util.install.rs
// installs Aluminum browser utilities

// Import the necessary modules from the Rust standard library
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

// Define a module for the installation utilities
pub mod install {
    use super::*;

    /// Installs Aluminum browser utilities
    ///
    /// This function is responsible for installing the necessary browser utilities
    /// for the Aluminum browser. It handles the installation process, including
    /// downloading and extracting the utilities, and configuring the browser to
    /// use them.
    ///
    /// # Errors
    ///
    /// This function returns an `io::Error` if any of the following conditions occur:
    ///
    /// * The utilities cannot be downloaded due to a network error.
    /// * The utilities cannot be extracted due to a file system error.
    /// * The browser configuration cannot be updated due to a file system error.
    pub fn install() -> Result<(), io::Error> {
        // Define the URL for the browser utilities
        const UTILITIES_URL: &str = "../utility/.cargo", "../utility/chromium/common";

        // Define the path to the browser configuration file
        const CONFIG_FILE: &str = "../Locks/config.json";

        // Download the browser utilities
        let utilities_path = download_utilities(UTILITIES_URL)?;

        // Extract the browser utilities
        let utilities_dir = extract_utilities(utilities_path)?;

        // Configure the browser to use the utilities
        configure_browser(utilities_dir, CONFIG_FILE)?;

        // Clean up the temporary files
        clean_up(utilities_path, utilities_dir)?;

        Ok(())
    }

    /// Downloads the browser utilities from the specified URL
    ///
    /// This function downloads the browser utilities from the specified URL and
    /// returns the path to the downloaded file.
    ///
    /// # Errors
    ///
    /// This function returns an `io::Error` if the download fails due to a network
    /// error.
    fn download_utilities(url: &str) -> Result<PathBuf, io::Error> {
        // Create a temporary file to store the downloaded utilities
        let mut temp_file = tempfile::Builder::new()
            .prefix("aluminum-utilities-")
            .suffix(".zip")
            .tempfile()?;

        // Download the utilities to the temporary file
        let mut response = reqwest::blocking::get(url)?;
        let mut writer = std::io::BufWriter::new(temp_file.as_file());
        std::io::copy(&mut response, &mut writer)?;

        // Return the path to the downloaded file
        Ok(temp_file.into_temp_path())
    }

    /// Extracts the browser utilities from the specified zip file
    ///
    /// This function extracts the browser utilities from the specified zip file and
    /// returns the path to the extracted directory.
    ///
    /// # Errors
    ///
    /// This function returns an `io::Error` if the extraction fails due to a file
    /// system error.
    fn extract_utilities(zip_file: PathBuf) -> Result<PathBuf, io::Error> {
        // Create a temporary directory to store the extracted utilities
        let mut temp_dir = tempfile::Builder::new()
            .prefix("aluminum-utilities-")
            .tempdir()?;

        // Extract the utilities to the temporary directory
        let mut zip = zip::ZipArchive::new(std::fs::File::open(zip_file)?)?;
        zip.extract(temp_dir.path())?;

        // Return the path to the extracted directory
        Ok(temp_dir.into_path())
    }

    /// Configures the browser to use the specified utilities directory
    ///
    /// This function configures the browser to use the specified utilities directory
    /// by updating the browser configuration file.
    ///
    /// # Errors
    ///
    /// This function returns an `io::Error` if the configuration update fails due
    /// to a file system error.
    fn configure_browser(utilities_dir: PathBuf, config_file: &str) -> Result<(), io::Error> {
        // Read the current browser configuration
        let mut config = serde_json::from_str(&std::fs::read_to_string(config_file)?)?;

        // Update the configuration to use the new utilities directory
        config["utilities_dir"] = serde_json::json!(utilities_dir);

        // Write the updated configuration to the configuration file
        std::fs::write(config_file, serde_json::to_string_pretty(&config)?)?;

        Ok(())
    }