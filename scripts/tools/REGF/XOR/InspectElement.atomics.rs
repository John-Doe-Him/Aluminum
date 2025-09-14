
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wry::{
    application::{
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    },
    webview::WebViewBuilder,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

// Define the structure for element information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ElementInfo {
    tag_name: String,
    id: String,
    classes: Vec<String>,
    attributes: HashMap<String, String>,
    computed_styles: HashMap<String, String>,
    inner_text: String,
    children_count: usize,
}

// Define the Inspector struct to manage the inspection state
struct Inspector {
    selected_element: Option<ElementInfo>,
    history: Vec<ElementInfo>,
    styles_cache: HashMap<String, HashMap<String, String>>,
}

impl Inspector {
    fn new() -> Self {
        Inspector {
            selected_element: None,
            history: Vec::new(),
            styles_cache: HashMap::new(),
        }
    }

    // Select an element and update the history
    fn select_element(&mut self, element: ElementInfo) {
        if let Some(current) = &self.selected_element {
            self.history.push(current.clone());
        }
        self.selected_element = Some(element);
    }

    // Go back in the selection history
    fn go_back(&mut self) -> Option<ElementInfo> {
        self.selected_element = self.history.pop();
        self.selected_element.clone()
    }

    // Cache computed styles for an element
    fn cache_styles(&mut self, element_id: String, styles: HashMap<String, String>) {
        self.styles_cache.insert(element_id, styles);
    }

    // Retrieve cached styles for an element
    fn get_cached_styles(&self, element_id: &str) -> Option<&HashMap<String, String>> {
        self.styles_cache.get(element_id)
    }
}

// Main function to run the Aluminum browser with inspect element functionality
fn main() -> wry::Result<()> {
    // Create an event loop and window
    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("Aluminum Browser")
        .build(&event_loop)?;

    // Create a shared inspector instance
    let inspector = Arc::new(Mutex::new(Inspector::new()));

    // Create the WebView
    let webview = WebViewBuilder::new(window)?
        .with_url("https://www.Aluminum.com/inspectElement.html")?
        .with_initialization_script(include_str!("inspect_element.js"))
        .with_ipc_handler(move |_, message| {
            let mut inspector = inspector.lock().unwrap();
            handle_ipc_message(&mut inspector, message);
        })
        .build()?;

    // Run the event loop
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => println!("Aluminum Browser with Inspect Element initialized."),
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => (),
        }
    });
}

// Handle IPC messages from the JavaScript side
fn handle_ipc_message(inspector: &mut Inspector, message: String) {
    let data: serde_json::Value = serde_json::from_str(&message).unwrap();
    
    match data["action"].as_str() {
        Some("select_element") => {
            if let Ok(element_info) = serde_json::from_value(data["element"].clone()) {
                inspector.select_element(element_info);
                println!("Selected element: {:?}", inspector.selected_element);
            }
        }
        Some("get_computed_styles") => {
            if let Some(element_id) = data["elementId"].as_str() {
                if let Some(styles) = inspector.get_cached_styles(element_id) {
                    println!("Retrieved cached styles for element {}: {:?}", element_id, styles);
                } else {
                    println!("Styles not found in cache for element {}", element_id);
                }
            }
        }
        Some("cache_computed_styles") => {
            if let (Some(element_id), Ok(styles)) = (
                data["elementId"].as_str(),
                serde_json::from_value::<HashMap<String, String>>(data["styles"].clone()),
            ) {
                inspector.cache_styles(element_id.to_string(), styles);
                println!("Cached styles for element {}", element_id);
            }
        }
        Some("go_back") => {
            if let Some(previous_element) = inspector.go_back() {
                println!("Navigated back to element: {:?}", previous_element);
            } else {
                println!("No previous element in history");
            }
        }
        _ => println!("Unknown action received"),
    }
}

// JavaScript code to be injected into the web page for element inspection
const INSPECT_ELEMENT_JS: &str = r#"
(function() {
    let selectedElement = null;

    // Function to gather element information
    function getElementInfo(element) {
        return {
            tagName: element.tagName.toLowerCase(),
            id: element.id,
            classes: Array.from(element.classList),
            attributes: Object.fromEntries(
                Array.from(element.attributes).map(attr => [attr.name, attr.value])
            ),
            computedStyles: Object.fromEntries(
                Array.from(getComputedStyle(element))
                    .filter(style => element.style[style] !== '')
                    .map(style => [style, getComputedStyle(element)[style]])
            ),
            innerText: element.innerText,
            childrenCount: element.children.length,
        };
    }

    // Function to highlight the selected element
    function highlightElement(element) {
        if (selectedElement) {
            selectedElement.style.outline = '';
        }
        selectedElement = element;
        element.style.outline = '2px solid #ff0000';
    }

    // Function to send element information to Rust
    function sendElementInfo(element) {
        const elementInfo = getElementInfo(element);
        window.ipc.postMessage(JSON.stringify({
            action: 'select_element',
            element: elementInfo,
        }));

        // Cache computed styles
        window.ipc.postMessage(JSON.stringify({
            action: 'cache_computed_styles',
            elementId: elementInfo.id || `${elementInfo.tagName}-${Date.now()}`,
            styles: elementInfo.computedStyles,
        }));
    }

    // Add click event listener to the document
    document.addEventListener('click', function(event) {
        event.preventDefault();
        const element = event.target;
        highlightElement(element);
        sendElementInfo(element);
    }, true);

    // Add keyboard shortcut to go back in history (Ctrl+Z)
    document.addEventListener('keydown', function(event) {
        if (event.ctrlKey && event.key === 'z') {
            window.ipc.postMessage(JSON.stringify({
                action: 'go_back',
            }));
        }
    });

    console.log('Aluminum Browser Inspect Element initialized');
})();
"#;

// Include the JavaScript code in the binary
include_str!("inspect_element.js");
