
// Devmode implementation for Aluminum web browser
// This module provides developer-oriented features and tools

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

// Define the DevMode struct to hold all developer tools and settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevMode {
    enabled: bool,
    console_log: Vec<String>,
    network_requests: Vec<NetworkRequest>,
    performance_metrics: PerformanceMetrics,
    dom_inspector: DomInspector,
    breakpoints: HashMap<String, Vec<usize>>,
    local_storage: HashMap<String, String>,
    cookies: Vec<Cookie>,
    user_agent: String,
    viewport_size: (u32, u32),
    emulation_settings: EmulationSettings,
}

// NetworkRequest struct to store information about network requests
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkRequest {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    body: Option<String>,
    response: Option<NetworkResponse>,
    timestamp: DateTime<Utc>,
}

// NetworkResponse struct to store information about network responses
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Option<String>,
}

// PerformanceMetrics struct to store various performance-related metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PerformanceMetrics {
    page_load_time: f64,
    dom_content_loaded: f64,
    first_paint: f64,
    first_contentful_paint: f64,
    largest_contentful_paint: f64,
    time_to_interactive: f64,
    memory_usage: u64,
}

// DomInspector struct to provide DOM inspection functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomInspector {
    selected_element: Option<String>,
    element_styles: HashMap<String, String>,
    element_attributes: HashMap<String, String>,
}

// Cookie struct to represent browser cookies
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    expires: Option<DateTime<Utc>>,
    secure: bool,
    http_only: bool,
}

// EmulationSettings struct to store device emulation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmulationSettings {
    device_name: String,
    user_agent: String,
    screen_size: (u32, u32),
    device_scale_factor: f32,
    touch_enabled: bool,
}

impl DevMode {
    // Create a new DevMode instance with default settings
    pub fn new() -> Self {
        DevMode {
            enabled: false,
            console_log: Vec::new(),
            network_requests: Vec::new(),
            performance_metrics: PerformanceMetrics::default(),
            dom_inspector: DomInspector::new(),
            breakpoints: HashMap::new(),
            local_storage: HashMap::new(),
            cookies: Vec::new(),
            user_agent: String::from("Aluminum/1.0"),
            viewport_size: (1920, 1080),
            emulation_settings: EmulationSettings::default(),
        }
    }

    // Enable or disable DevMode
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    // Add a console log entry
    pub fn add_console_log(&mut self, message: String) {
        if self.enabled {
            self.console_log.push(message);
        }
    }

    // Record a network request
    pub fn record_network_request(&mut self, request: NetworkRequest) {
        if self.enabled {
            self.network_requests.push(request);
        }
    }

    // Update performance metrics
    pub fn update_performance_metrics(&mut self, metrics: PerformanceMetrics) {
        if self.enabled {
            self.performance_metrics = metrics;
        }
    }

    // Select an element in the DOM inspector
    pub fn select_element(&mut self, element_selector: String) {
        if self.enabled {
            self.dom_inspector.selected_element = Some(element_selector);
        }
    }

    // Set a breakpoint in the code
    pub fn set_breakpoint(&mut self, file_path: String, line_number: usize) {
        if self.enabled {
            self.breakpoints.entry(file_path).or_insert_with(Vec::new).push(line_number);
        }
    }

    // Remove a breakpoint from the code
    pub fn remove_breakpoint(&mut self, file_path: String, line_number: usize) {
        if self.enabled {
            if let Some(breakpoints) = self.breakpoints.get_mut(&file_path) {
                breakpoints.retain(|&x| x != line_number);
            }
        }
    }

    // Set a local storage item
    pub fn set_local_storage(&mut self, key: String, value: String) {
        if self.enabled {
            self.local_storage.insert(key, value);
        }
    }

    // Get a local storage item
    pub fn get_local_storage(&self, key: &str) -> Option<&String> {
        if self.enabled {
            self.local_storage.get(key)
        } else {
            None
        }
    }

    // Add a cookie
    pub fn add_cookie(&mut self, cookie: Cookie) {
        if self.enabled {
            self.cookies.push(cookie);
        }
    }

    // Remove a cookie
    pub fn remove_cookie(&mut self, name: &str) {
        if self.enabled {
            self.cookies.retain(|c| c.name != name);
        }
    }

    // Set the user agent
    pub fn set_user_agent(&mut self, user_agent: String) {
        if self.enabled {
            self.user_agent = user_agent;
        }
    }

    // Set the viewport size
    pub fn set_viewport_size(&mut self, width: u32, height: u32) {
        if self.enabled {
            self.viewport_size = (width, height);
        }
    }

    // Set device emulation settings
    pub fn set_emulation_settings(&mut self, settings: EmulationSettings) {
        if self.enabled {
            self.emulation_settings = settings;
        }
    }

    // Clear all DevMode data
    pub fn clear_data(&mut self) {
        if self.enabled {
            self.console_log.clear();
            self.network_requests.clear();
            self.performance_metrics = PerformanceMetrics::default();
            self.dom_inspector = DomInspector::new();
            self.breakpoints.clear();
            self.local_storage.clear();
            self.cookies.clear();
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        PerformanceMetrics {
            page_load_time: 0.0,
            dom_content_loaded: 0.0,
            first_paint: 0.0,
            first_contentful_paint: 0.0,
            largest_contentful_paint: 0.0,
            time_to_interactive: 0.0,
            memory_usage: 0,
        }
    }
}

impl DomInspector {
    fn new() -> Self {
        DomInspector {
            selected_element: None,
            element_styles: HashMap::new(),
            element_attributes: HashMap::new(),
        }
    }
}

impl Default for EmulationSettings {
    fn default() -> Self {
        EmulationSettings {
            device_name: String::from("Default"),
            user_agent: String::from("Aluminum/1.0"),
            screen_size: (1920, 1080),
            device_scale_factor: 1.0,
            touch_enabled: false,
        }
    }
}

// Create a global DevMode instance wrapped in a mutex for thread-safe access
lazy_static! {
    static ref DEVMODE: Arc<Mutex<DevMode>> = Arc::new(Mutex::new(DevMode::new()));
}

// Public functions to interact with the global DevMode instance

pub fn enable_devmode(enabled: bool) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.set_enabled(enabled);
}

pub fn add_console_log(message: String) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.add_console_log(message);
}

pub fn record_network_request(request: NetworkRequest) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.record_network_request(request);
}

pub fn update_performance_metrics(metrics: PerformanceMetrics) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.update_performance_metrics(metrics);
}

pub fn select_element(element_selector: String) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.select_element(element_selector);
}

pub fn set_breakpoint(file_path: String, line_number: usize) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.set_breakpoint(file_path, line_number);
}

pub fn remove_breakpoint(file_path: String, line_number: usize) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.remove_breakpoint(file_path, line_number);
}

pub fn set_local_storage(key: String, value: String) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.set_local_storage(key, value);
}

pub fn get_local_storage(key: &str) -> Option<String> {
    let devmode = DEVMODE.lock().unwrap();
    devmode.get_local_storage(key).cloned()
}

pub fn add_cookie(cookie: Cookie) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.add_cookie(cookie);
}

pub fn remove_cookie(name: &str) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.remove_cookie(name);
}

pub fn set_user_agent(user_agent: String) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.set_user_agent(user_agent);
}

pub fn set_viewport_size(width: u32, height: u32) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.set_viewport_size(width, height);
}

pub fn set_emulation_settings(settings: EmulationSettings) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.set_emulation_settings(settings);
}

pub fn clear_devmode_data() {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.clear_data();
}

// Additional helper functions for DevMode functionality

pub fn get_performance_summary() -> String {
    let devmode = DEVMODE.lock().unwrap();
    format!(
        "Page Load Time: {:.2}s\nDOM Content Loaded: {:.2}s\nFirst Paint: {:.2}s\nFirst Contentful Paint: {:.2}s\nLargest Contentful Paint: {:.2}s\nTime to Interactive: {:.2}s\nMemory Usage: {} bytes",
        devmode.performance_metrics.page_load_time,
        devmode.performance_metrics.dom_content_loaded,
        devmode.performance_metrics.first_paint,
        devmode.performance_metrics.first_contentful_paint,
        devmode.performance_metrics.largest_contentful_paint,
        devmode.performance_metrics.time_to_interactive,
        devmode.performance_metrics.memory_usage
    )
}

pub fn get_network_requests_summary() -> String {
    let devmode = DEVMODE.lock().unwrap();
    let mut summary = String::new();
    for (index, request) in devmode.network_requests.iter().enumerate() {
        summary.push_str(&format!(
            "Request {}: {} {} (Status: {})\n",
            index + 1,
            request.method,
            request.url,
            request.response.as_ref().map_or(0, |r| r.status)
        ));
    }
    summary
}

pub fn get_dom_inspector_info() -> String {
    let devmode = DEVMODE.lock().unwrap();
    let mut info = String::new();
    if let Some(element) = &devmode.dom_inspector.selected_element {
        info.push_str(&format!("Selected Element: {}\n", element));
        info.push_str("Styles:\n");
        for (property, value) in &devmode.dom_inspector.element_styles {
            info.push_str(&format!("  {}: {}\n", property, value));
        }
        info.push_str("Attributes:\n");
        for (name, value) in &devmode.dom_inspector.element_attributes {
            info.push_str(&format!("  {}: {}\n", name, value));
        }
    } else {
        info.push_str("No element selected");
    }
    info
}

// Function to initialize DevMode with custom settings
pub fn initialize_devmode(settings: DevModeSettings) {
    let mut devmode = DEVMODE.lock().unwrap();
    devmode.set_enabled(settings.enabled);
    devmode.set_user_agent(settings.user_agent);
    devmode.set_viewport_size(settings.viewport_width, settings.viewport_height);
    devmode.set_emulation_settings(settings.emulation_settings);
}

// DevModeSettings struct for initialization
pub struct DevModeSettings {
    pub enabled: bool,
    pub user_agent: String,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub emulation_settings: EmulationSettings,
}

// Function to export DevMode data for debugging purposes
pub fn export_devmode_data() -> String {
    let devmode = DEVMODE.lock().unwrap();
    serde_json::to_string_pretty(&*devmode).unwrap_or_else(|_| String::from("Failed to export DevMode data"))
}

// Function to import DevMode data
pub fn import_devmode_data(data: &str) -> Result<(), serde_json::Error> {
    let imported_devmode: DevMode = serde_json::from_str(data)?;
    let mut devmode = DEVMODE.lock().unwrap();
    *devmode = imported_devmode;
    Ok(())
}

// Function to generate a comprehensive DevMode report
pub fn generate_devmode_report() -> String {
    let devmode = DEVMODE.lock().unwrap();
    let mut report = String::new();

    report.push_str("=== Aluminum Browser DevMode Report ===\n\n");
    report.push_str(&format!("DevMode Enabled: {}\n", devmode.enabled));
    report.push_str(&format!("User Agent: {}\n", devmode.user_agent));
    report.push_str(&format!("Viewport Size: {}x{}\n\n", devmode.viewport_size.0, devmode.viewport_size.1));

    report.push_str("Performance Metrics:\n");
    report.
