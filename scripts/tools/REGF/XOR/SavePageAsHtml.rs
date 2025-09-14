
use std::fs::File;
use std::io::Write;
use std::path::Path;
use reqwest;
use scraper::{Html, Selector};
use url::Url;
use chrono::Utc;
use mime_guess::from_path;
use base64;
use image;
use tokio;

// Configuration struct for the HTML saving process
struct SaveConfig {
    include_styles: bool,
    include_scripts: bool,
    embed_images: bool,
    minify: bool,
    add_timestamp: bool,
}

impl Default for SaveConfig {
    fn default() -> Self {
        SaveConfig {
            include_styles: true,
            include_scripts: true,
            embed_images: true,
            minify: false,
            add_timestamp: true,
        }
    }
}

// Main function to save a page as HTML
pub async fn save_page_as_html(url: &str, output_path: &str, config: SaveConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Fetch the HTML content
    let html_content = fetch_html_content(url).await?;

    // Parse the HTML
    let document = Html::parse_document(&html_content);

    // Process the HTML
    let processed_html = process_html(&document, url, &config).await?;

    // Save the processed HTML
    save_html_to_file(&processed_html, output_path, &config)?;

    println!("Page saved successfully as HTML: {}", output_path);
    Ok(())
}

// Fetch HTML content from the given URL
async fn fetch_html_content(url: &str) -> Result<String, reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    response.text().await
}

// Process the HTML document
async fn process_html(document: &Html, base_url: &str, config: &SaveConfig) -> Result<String, Box<dyn std::error::Error>> {
    let mut processed_html = document.root_element().html();

    if config.include_styles {
        processed_html = process_styles(processed_html, base_url).await?;
    }

    if config.include_scripts {
        processed_html = process_scripts(processed_html, base_url).await?;
    }

    if config.embed_images {
        processed_html = process_images(processed_html, base_url).await?;
    }

    if config.minify {
        processed_html = minify_html(&processed_html);
    }

    if config.add_timestamp {
        processed_html = add_timestamp(processed_html);
    }

    Ok(processed_html)
}

// Process and inline CSS styles
async fn process_styles(html: String, base_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let document = Html::parse_document(&html);
    let style_selector = Selector::parse("link[rel='stylesheet']").unwrap();

    let mut inline_styles = String::new();
    for element in document.select(&style_selector) {
        if let Some(href) = element.value().attr("href") {
            let style_url = Url::parse(base_url)?.join(href)?;
            let style_content = fetch_html_content(style_url.as_str()).await?;
            inline_styles.push_str(&format!("<style>{}</style>", style_content));
        }
    }

    let processed_html = html.replace("</head>", &format!("{}</head>", inline_styles));
    Ok(processed_html)
}

// Process and inline JavaScript
async fn process_scripts(html: String, base_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let document = Html::parse_document(&html);
    let script_selector = Selector::parse("script[src]").unwrap();

    let mut inline_scripts = String::new();
    for element in document.select(&script_selector) {
        if let Some(src) = element.value().attr("src") {
            let script_url = Url::parse(base_url)?.join(src)?;
            let script_content = fetch_html_content(script_url.as_str()).await?;
            inline_scripts.push_str(&format!("<script>{}</script>", script_content));
        }
    }

    let processed_html = html.replace("</body>", &format!("{}</body>", inline_scripts));
    Ok(processed_html)
}

// Process and embed images
async fn process_images(html: String, base_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let document = Html::parse_document(&html);
    let img_selector = Selector::parse("img[src]").unwrap();

    let mut processed_html = html.clone();
    for element in document.select(&img_selector) {
        if let Some(src) = element.value().attr("src") {
            let img_url = Url::parse(base_url)?.join(src)?;
            let img_content = fetch_image_content(img_url.as_str()).await?;
            let img_base64 = base64::encode(&img_content);
            let mime_type = from_path(src).first_or_octet_stream().to_string();
            let data_url = format!("data:{};base64,{}", mime_type, img_base64);
            processed_html = processed_html.replace(src, &data_url);
        }
    }

    Ok(processed_html)
}

// Fetch image content
async fn fetch_image_content(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}

// Minify HTML content
fn minify_html(html: &str) -> String {
    // This is a simple minification. For production use, consider using a dedicated HTML minifier library.
    html.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<&str>>()
        .join("")
}

// Add timestamp to the HTML
fn add_timestamp(html: String) -> String {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let timestamp_comment = format!("<!-- Saved on: {} -->", timestamp);
    html.replace("</body>", &format!("{}\n</body>", timestamp_comment))
}

// Save the processed HTML to a file
fn save_html_to_file(html: &str, output_path: &str, config: &SaveConfig) -> std::io::Result<()> {
    let mut file = File::create(output_path)?;
    file.write_all(html.as_bytes())?;
    
    if config.add_timestamp {
        let metadata = file.metadata()?;
        let created = metadata.created()?;
        filetime::set_file_mtime(output_path, filetime::FileTime::from_system_time(created))?;
    }
    
    Ok(())
}

// Example usage
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "https://www.Aluminum.com/DX/{}";
    let output_path = "saved_page.html";
    let config = SaveConfig {
        include_styles: true,
        include_scripts: true,
        embed_images: true,
        minify: false,
        add_timestamp: true,
    };

    save_page_as_html(url, output_path, config).await?;
    Ok(())
}
