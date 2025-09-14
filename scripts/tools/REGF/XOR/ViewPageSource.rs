
use std::io::{self, Write};
use reqwest;
use colored::*;
use html5ever::parse_document;
use html5ever::rcdom::{RcDom, Handle, NodeData};
use markup5ever_rcdom as rcdom;
use std::default::Default;
use std::fs::File;
use std::path::Path;
use std::time::Instant;
use indicatif::{ProgressBar, ProgressStyle};

// Constants for configuration
const USER_AGENT: &str = "Aluminum/1.0";
const TIMEOUT_SECONDS: u64 = 30;
const MAX_REDIRECTS: usize = 5;

/// Struct to hold page source information
struct PageSource {
    url: String,
    content: String,
    status_code: u16,
    headers: reqwest::header::HeaderMap,
}

/// Function to fetch the page source
async fn fetch_page_source(url: &str) -> Result<PageSource, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECONDS))
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        .build()?;

    let response = client.get(url).send().await?;
    let status_code = response.status().as_u16();
    let headers = response.headers().clone();
    let content = response.text().await?;

    Ok(PageSource {
        url: url.to_string(),
        content,
        status_code,
        headers,
    })
}

/// Function to parse and pretty print HTML
fn pretty_print_html(content: &str) -> String {
    let mut pretty_html = String::new();
    let dom = parse_document(RcDom::default(), Default::default())
        .from_utf8()
        .read_from(&mut content.as_bytes())
        .unwrap();

    fn walk(indent: usize, handle: &Handle, pretty_html: &mut String) {
        let node = handle;
        match node.data {
            NodeData::Element { ref name, ref attrs, .. } => {
                pretty_html.push_str(&"  ".repeat(indent));
                pretty_html.push_str(&format!("<{}", name.local));
                for attr in attrs.borrow().iter() {
                    pretty_html.push_str(&format!(" {}=\"{}\"", attr.name.local, attr.value));
                }
                pretty_html.push_str(">\n");
                for child in node.children.borrow().iter() {
                    walk(indent + 1, child, pretty_html);
                }
                pretty_html.push_str(&"  ".repeat(indent));
                pretty_html.push_str(&format!("</{}>\n", name.local));
            }
            NodeData::Text { ref contents } => {
                let text = contents.borrow().trim();
                if !text.is_empty() {
                    pretty_html.push_str(&"  ".repeat(indent));
                    pretty_html.push_str(&format!("{}\n", text));
                }
            }
            _ => {}
        }
    }

    walk(0, &dom.document, &mut pretty_html);
    pretty_html
}

/// Function to save content to a file
fn save_to_file(content: &str, filename: &str) -> io::Result<()> {
    let path = Path::new(filename);
    let mut file = File::create(&path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

/// Main function to view page source
pub async fn view_page_source() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Aluminum Web Browser - View Page Source".bold().green());
    println!("Enter the URL of the page you want to view the source of:");
    
    let mut url = String::new();
    io::stdin().read_line(&mut url)?;
    let url = url.trim();

    // Show loading spinner
    let spinner_style = ProgressStyle::default_spinner()
        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        .template("{spinner:.green} {msg}");
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style);
    spinner.set_message("Fetching page source...");

    // Measure execution time
    let start_time = Instant::now();

    // Fetch page source
    let page_source = fetch_page_source(url).await?;

    // Stop spinner
    spinner.finish_with_message("Page source fetched successfully!");

    // Display basic information
    println!("\n{}", "Page Information:".bold().cyan());
    println!("URL: {}", page_source.url);
    println!("Status Code: {}", page_source.status_code);
    println!("Content Length: {} bytes", page_source.content.len());

    // Display headers
    println!("\n{}", "Headers:".bold().cyan());
    for (key, value) in page_source.headers.iter() {
        println!("{}: {}", key.to_string().yellow(), value.to_str().unwrap_or("Unable to display"));
    }

    // Pretty print HTML
    let pretty_html = pretty_print_html(&page_source.content);

    // Display options
    println!("\n{}", "Options:".bold().cyan());
    println!("1. View raw source");
    println!("2. View pretty printed source");
    println!("3. Save raw source to file");
    println!("4. Save pretty printed source to file");
    println!("5. Exit");

    loop {
        println!("\nEnter your choice (1-5):");
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        match choice.trim() {
            "1" => println!("{}", page_source.content),
            "2" => println!("{}", pretty_html),
            "3" => {
                save_to_file(&page_source.content, "raw_source.html")?;
                println!("Raw source saved to 'raw_source.html'");
            },
            "4" => {
                save_to_file(&pretty_html, "pretty_source.html")?;
                println!("Pretty printed source saved to 'pretty_source.html'");
            },
            "5" => break,
            _ => println!("Invalid choice. Please enter a number between 1 and 5."),
        }
    }

    // Display execution time
    let duration = start_time.elapsed();
    println!("\nExecution time: {:.2?}", duration);

    Ok(())
}

// Error handling wrapper for the main function
pub fn run_view_page_source() {
    match view_page_source() {
        Ok(_) => println!("Page source viewer completed successfully."),
        Err(e) => eprintln!("An error occurred: {}", e),
    }
}
