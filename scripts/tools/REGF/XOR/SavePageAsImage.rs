
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use image::{ImageBuffer, Rgba};
use reqwest;
use scraper::{Html, Selector};
use headless_chrome::{Browser, LaunchOptions};
use base64;
use serde_json;

// Constants for configuration
const DEFAULT_SAVE_PATH: &str = "./saved_pages";
const DEFAULT_IMAGE_FORMAT: &str = "png";
const DEFAULT_VIEWPORT_WIDTH: u32 = 1920;
const DEFAULT_VIEWPORT_HEIGHT: u32 = 1080;

/// SavePageAsImage struct to encapsulate the functionality
pub struct SavePageAsImage {
    save_path: String,
    image_format: String,
    viewport_width: u32,
    viewport_height: u32,
}

impl SavePageAsImage {
    /// Create a new instance of SavePageAsImage with default values
    pub fn new() -> Self {
        SavePageAsImage {
            save_path: DEFAULT_SAVE_PATH.to_string(),
            image_format: DEFAULT_IMAGE_FORMAT.to_string(),
            viewport_width: DEFAULT_VIEWPORT_WIDTH,
            viewport_height: DEFAULT_VIEWPORT_HEIGHT,
        }
    }

    /// Set custom save path for images
    pub fn set_save_path(&mut self, path: &str) {
        self.save_path = path.to_string();
    }

    /// Set custom image format
    pub fn set_image_format(&mut self, format: &str) {
        self.image_format = format.to_string();
    }

    /// Set custom viewport dimensions
    pub fn set_viewport(&mut self, width: u32, height: u32) {
        self.viewport_width = width;
        self.viewport_height = height;
    }

    /// Save the webpage as an image
    pub fn save(&self, url: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Ensure save directory exists
        fs::create_dir_all(&self.save_path)?;

        // Launch headless browser
        let browser = Browser::new(LaunchOptions {
            headless: true,
            ..Default::default()
        })?;

        // Create a new page and navigate to the URL
        let tab = browser.new_tab()?;
        tab.navigate_to(url)?;
        tab.wait_until_navigated()?;

        // Set viewport size
        tab.set_viewport(self.viewport_width, self.viewport_height)?;

        // Capture screenshot
        let screenshot = tab.capture_screenshot(
            headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
            None,
            None,
            true,
        )?;

        // Generate filename
        let filename = self.generate_filename(url);
        let full_path = format!("{}/{}.{}", self.save_path, filename, self.image_format);

        // Save the image
        fs::write(&full_path, screenshot)?;

        Ok(full_path)
    }

    /// Generate a unique filename based on the URL and current timestamp
    fn generate_filename(&self, url: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let url_hash = md5::compute(url);
        format!("page_{}_{:x}", timestamp, url_hash)
    }

    /// Extract and save all images from the webpage
    pub fn save_all_images(&self, url: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut saved_images = Vec::new();

        // Fetch the HTML content
        let html_content = reqwest::blocking::get(url)?.text()?;
        let document = Html::parse_document(&html_content);

        // Select all image elements
        let img_selector = Selector::parse("img").unwrap();
        for img in document.select(&img_selector) {
            if let Some(src) = img.value().attr("src") {
                let img_url = if src.starts_with("http") {
                    src.to_string()
                } else {
                    format!("{}{}", url, src)
                };

                // Download and save the image
                match self.download_and_save_image(&img_url) {
                    Ok(path) => saved_images.push(path),
                    Err(e) => eprintln!("Failed to save image {}: {}", img_url, e),
                }
            }
        }

        Ok(saved_images)
    }

    /// Download and save an individual image
    fn download_and_save_image(&self, img_url: &str) -> Result<String, Box<dyn std::error::Error>> {
        let response = reqwest::blocking::get(img_url)?;
        let img_content = response.bytes()?;

        let img = image::load_from_memory(&img_content)?;
        let filename = self.generate_filename(img_url);
        let full_path = format!("{}/{}.{}", self.save_path, filename, self.image_format);

        img.save_with_format(&full_path, image::ImageFormat::Png)?;

        Ok(full_path)
    }

    /// Generate a full page screenshot by scrolling and stitching multiple screenshots
    pub fn full_page_screenshot(&self, url: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Launch headless browser
        let browser = Browser::new(LaunchOptions {
            headless: true,
            ..Default::default()
        })?;

        // Create a new page and navigate to the URL
        let tab = browser.new_tab()?;
        tab.navigate_to(url)?;
        tab.wait_until_navigated()?;

        // Set initial viewport size
        tab.set_viewport(self.viewport_width, self.viewport_height)?;

        // Get full page height
        let full_height: u32 = tab.evaluate("document.body.scrollHeight")?.value.unwrap().as_u64().unwrap() as u32;

        // Calculate number of screenshots needed
        let num_screenshots = (full_height as f32 / self.viewport_height as f32).ceil() as u32;

        // Create a buffer to store the full page image
        let mut full_page_buffer = ImageBuffer::new(self.viewport_width, full_height);

        for i in 0..num_screenshots {
            // Scroll to the appropriate position
            let scroll_y = i * self.viewport_height;
            tab.evaluate(&format!("window.scrollTo(0, {})", scroll_y))?;

            // Capture screenshot
            let screenshot = tab.capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                None,
                None,
                true,
            )?;

            // Convert screenshot to image buffer
            let img = image::load_from_memory(&screenshot)?;

            // Copy screenshot to the appropriate position in the full page buffer
            image::imageops::replace(&mut full_page_buffer, &img, 0, scroll_y);
        }

        // Generate filename and save the full page screenshot
        let filename = self.generate_filename(url);
        let full_path = format!("{}/{}_full.{}", self.save_path, filename, self.image_format);
        full_page_buffer.save_with_format(&full_path, image::ImageFormat::Png)?;

        Ok(full_path)
    }

    /// Generate a PDF version of the webpage
    pub fn save_as_pdf(&self, url: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Launch headless browser
        let browser = Browser::new(LaunchOptions {
            headless: true,
            ..Default::default()
        })?;

        // Create a new page and navigate to the URL
        let tab = browser.new_tab()?;
        tab.navigate_to(url)?;
        tab.wait_until_navigated()?;

        // Set print options
        let print_options = serde_json::json!({
            "landscape": false,
            "printBackground": true,
            "paperWidth": 8.5,
            "paperHeight": 11,
            "marginTop": 0.4,
            "marginBottom": 0.4,
            "marginLeft": 0.4,
            "marginRight": 0.4,
        });

        // Generate PDF
        let pdf_data = tab.print_to_pdf(Some(print_options))?;

        // Generate filename and save the PDF
        let filename = self.generate_filename(url);
        let full_path = format!("{}/{}.pdf", self.save_path, filename);
        fs::write(&full_path, pdf_data)?;

        Ok(full_path)
    }

    /// Extract and save text content from the webpage
    pub fn save_text_content(&self, url: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Fetch the HTML content
        let html_content = reqwest::blocking::get(url)?.text()?;
        let document = Html::parse_document(&html_content);

        // Extract text content
        let body_selector = Selector::parse("body").unwrap();
        let body = document.select(&body_selector).next().unwrap();
        let text_content = body.text().collect::<Vec<_>>().join("\n");

        // Generate filename and save the text content
        let filename = self.generate_filename(url);
        let full_path = format!("{}/{}.txt", self.save_path, filename);
        fs::write(&full_path, text_content)?;

        Ok(full_path)
    }

    /// Save webpage metadata (title, description, keywords)
    pub fn save_metadata(&self, url: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Fetch the HTML content
        let html_content = reqwest::blocking::get(url)?.text()?;
        let document = Html::parse_document(&html_content);

        // Extract metadata
        let title = document
            .select(&Selector::parse("title").unwrap())
            .next()
            .map(|t| t.inner_html())
            .unwrap_or_default();

        let description = document
            .select(&Selector::parse("meta[name='description']").unwrap())
            .next()
            .and_then(|m| m.value().attr("content"))
            .unwrap_or_default();

        let keywords = document
            .select(&Selector::parse("meta[name='keywords']").unwrap())
            .next()
            .and_then(|m| m.value().attr("content"))
            .unwrap_or_default();

        // Create metadata JSON
        let metadata = serde_json::json!({
            "url": url,
            "title": title,
            "description": description,
            "keywords": keywords,
        });

        // Generate filename and save the metadata
        let filename = self.generate_filename(url);
        let full_path = format!("{}/{}_metadata.json", self.save_path, filename);
        fs::write(&full_path, serde_json::to_string_pretty(&metadata)?)?;

        Ok(full_path)
    }
}

// Example usage
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut save_tool = SavePageAsImage::new();
    save_tool.set_save_path("./aluminum_saved_pages");
    save_tool.set_viewport(1440, 900);

    let url = "";

    // Save page as image
    let image_path = save_tool.save(url)?;
    println!("Page saved as image: {}", image_path);

    // Save all images from the page
    let saved_images = save_tool.save_all_images(url)?;
    println!("Saved {} images from the page", saved_images.len());

    // Generate full page screenshot
    let full_page_path = save_tool.full_page_screenshot(url)?;
    println!("Full page screenshot saved: {}", full_page_path);

    // Save page as PDF
    let pdf_path = save_tool.save_as_pdf(url)?;
    println!("Page saved as PDF: {}", pdf_path);

    // Save text content
    let text_path = save_tool.save_text_content(url)?;
    println!("Text content saved: {}", text_path);

    // Save metadata
    let metadata_path = save_tool.save_metadata(url)?;
    println!("Metadata saved: {}", metadata_path);

    Ok(())
}
