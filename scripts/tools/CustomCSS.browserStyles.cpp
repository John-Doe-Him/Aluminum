
// CustomCSS.browserStyles.cpp
// Custom CSS Browser Styling for Aluminum Browser

#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <regex>
#include <memory>
#include <stdexcept>

namespace Aluminum {
namespace CustomCSS {

class BrowserStyleManager {
public:
    BrowserStyleManager() {
        initializeDefaultStyles();
    }

    // Apply custom styles to the browser
    void applyCustomStyles(const std::string& customCSS) {
        // Parse and validate the custom CSS
        std::string sanitizedCSS = sanitizeCSS(customCSS);
        
        // Merge custom styles with default styles
        mergeStyles(sanitizedCSS);

        // Apply the merged styles to the browser UI
        updateBrowserUI();

    }

private:
    std::map<std::string, std::string> defaultStyles;
    std::map<std::string, std::string> customStyles;

    // Initialize default browser styles
    void initializeDefaultStyles() {
        defaultStyles["body"] = "font-family: Arial, sans-serif; font-size: 14px; line-height: 1.6;";
        defaultStyles["a"] = "color: #0066cc; text-decoration: none;";
        defaultStyles["a:hover"] = "text-decoration: underline;";
        defaultStyles["h1"] = "font-size: 24px; color: #333333;";
        defaultStyles["h2"] = "font-size: 20px; color: #444444;";
        defaultStyles["h3"] = "font-size: 18px; color: #555555;";
        defaultStyles["input[type='text']"] = "padding: 5px; border: 1px solid #cccccc; border-radius: 3px;";
        defaultStyles["button"] = "background-color: #0066cc; color: white; padding: 8px 15px; border: none; border-radius: 3px; cursor: pointer;";
        
        // Add more default styles as needed
    }

    // Sanitize and validate custom CSS input
    std::string sanitizeCSS(const std::string& css) {
        // Remove potentially harmful CSS
        std::string sanitized = removeHarmfulCSS(css);

        // Validate CSS syntax
        if (!isValidCSS(sanitized)) {
            throw std::runtime_error("Invalid CSS syntax detected");
        }

        return sanitized;
    }

    // Remove potentially harmful CSS properties and values
    std::string removeHarmfulCSS(const std::string& css) {
        std::vector<std::string> harmfulProperties = {
            "position", "top", "left", "bottom", "right", "z-index", "overflow"
        };

        std::string result = css;
        for (const auto& prop : harmfulProperties) {
            std::regex pattern(prop + "\\s*:");
            result = std::regex_replace(result, pattern, "/* Removed for security: " + prop + ": */");
        }

        return result;
    }

    // Validate CSS syntax (simplified version, consider using a proper CSS parser for production)
    bool isValidCSS(const std::string& css) {
        // Simple check for balanced braces
        int braceCount = 0;
        for (char c : css) {
            if (c == '{') braceCount++;
            if (c == '}') braceCount--;
            if (braceCount < 0) return false;
        }
        return braceCount == 0;
    }

    // Merge custom styles with default styles
    void mergeStyles(const std::string& customCSS) {
        std::istringstream stream(customCSS);
        std::string line;
        std::string currentSelector;

        while (std::getline(stream, line)) {
            line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
            line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);
            if (line.empty()) continue;

            if (line[0] == '}') {
                currentSelector.clear();
            } else if (line.back() == '{') {
                currentSelector = line.substr(0, line.length() - 1);
                currentSelector.erase(0, currentSelector.find_first_not_of(" \t\n\r\f\v"));
                currentSelector.erase(currentSelector.find_last_not_of(" \t\n\r\f\v") + 1);
            } else if (!currentSelector.empty()) {
                customStyles[currentSelector] += line;
            }
        }

        // Merge custom styles with default styles
        for (const auto& style : customStyles) {
            if (defaultStyles.find(style.first) != defaultStyles.end()) {
                defaultStyles[style.first] += style.second;
            } else {
                defaultStyles[style.first] = style.second;
            }
        }
    }    // Update the browser UI with the merged styles
                void updateBrowserUI() {
                    std::string combinedCSS;
                    for (const auto& style : defaultStyles) {
                        combinedCSS += style.first + " { " + style.second + " }\n";
                    }

                    // Update specific UI elements
                    updateAddressBar();
                    updateTabBar();
                    updateToolbar();
                    updateContextMenu();
                    updateScrollbars();
                }
    // Update the address bar styling
    void updateAddressBar() {
        // Implementation for updating address bar styles
        // ...
    }

    // Update the tab bar styling
    void updateTabBar() {
        // Implementation for updating tab bar styles
        // ...
    }

    // Update the toolbar styling
    void updateToolbar() {
        // Implementation for updating toolbar styles
        // ...
    }

    // Update the context menu styling
    void updateContextMenu() {
        // Implementation for updating context menu styles
        // ...
    }

    // Update the scrollbar styling
    void updateScrollbars() {
        // Implementation for updating scrollbar styles
        // ...
    }
};

// Singleton instance of BrowserStyleManager
BrowserStyleManager& getBrowserStyleManager() {
    static BrowserStyleManager instance;
    return instance;
}

// Public function to apply custom CSS to the Aluminum browser
void applyCustomBrowserStyles(const std::string& customCSS) {
    try {
        BrowserStyleManager& styleManager = getBrowserStyleManager();
        styleManager.applyCustomStyles(customCSS);
    } catch (const std::exception& e) {
        // Handle the error (e.g., show an error message to the user)
    }
}// Function to load custom CSS from a file
std::string loadCustomCSSFromFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open CSS file: " + filePath);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Function to save custom CSS to a file
void saveCustomCSSToFile(const std::string& customCSS, const std::string& filePath) {
    std::ofstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file for writing: " + filePath);
    }

    file << customCSS;
    file.close();

    // Use a logging library or custom logging function instead of spdlog
    // For example, you can use std::cout for simple logging
    std::cout << "Custom CSS saved to file: " << filePath << std::endl;
}
// Function to generate a default custom CSS template
std::string generateDefaultCustomCSSTemplate() {
    return R"(
/* Aluminum Browser Custom CSS Template */

/* Global Styles */
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 16px;
    line-height: 1.6;
    color: #333333;
    background-color: #f5f5f5;
}

/* Links */
a {
    color: #0078d4;
    text-decoration: none;
    transition: color 0.3s ease;
}

a:hover {
    color: #0056b3;
    text-decoration: underline;
}

/* Headings */
h1, h2, h3, h4, h5, h6 {
    font-weight: 600;
    margin-top: 1em;
    margin-bottom: 0.5em;
}

h1 { font-size: 2.5em; color: #2c3e50; }
h2 { font-size: 2em; color: #34495e; }
h3 { font-size: 1.75em; color: #455a64; }
h4 { font-size: 1.5em; color: #546e7a; }
h5 { font-size: 1.25em; color: #607d8b; }
h6 { font-size: 1em; color: #78909c; }

/* Form Elements */
input[type="text"],
input[type="password"],
input[type="email"],
input[type="number"],
textarea {
    padding: 8px 12px;
    border: 1px solid #cccccc;
    border-radius: 4px;
    font-size: 14px;
    transition: border-color 0.3s ease;
}

input[type="text"]:focus,
input[type="password"]:focus,
input[type="email"]:focus,
input[type="number"]:focus,
textarea:focus {
    border-color: #0078d4;
    outline: none;
    box-shadow: 0 0 0 2px rgba(0, 120, 212, 0.2);
}

button {
    background-color: #0078d4;
    color: white;
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    font-size: 14px;
    cursor: pointer;
    transition: background-color 0.3s ease;
}

button:hover {
    background-color: #0056b3;
}

/* Custom Classes */
.aluminum-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.aluminum-card {
    background-color: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    padding: 20px;
    margin-bottom: 20px;
}

.aluminum-btn-primary {
    background-color: #0078d4;
    color: white;
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    font-size: 14px;
    cursor: pointer;
    transition: background-color 0.3s ease;
}

.aluminum-btn-primary:hover {
    background-color: #0056b3;
}

.aluminum-btn-secondary {
    background-color: #f0f0f0;
    color: #333333;
    padding: 10px 20px;
    border: 1px solid #cccccc;
    border-radius: 4px;
    font-size: 14px;
    cursor: pointer;
    transition: background-color 0.3s ease;
}

.aluminum-btn-secondary:hover {
    background-color: #e0e0e0;
}

/* Add more custom styles as needed */
)";
}

} // namespace CustomCSS
} // namespace Aluminum
