
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <ctime>

// Forward declarations
class Tab;
class WebBrowser;

// Tab class to represent a single browser tab
class Tab {
private:
    std::string url;
    std::string title;
    bool isLoading;
    std::chrono::system_clock::time_point lastAccessed;

public:
    Tab(const std::string& initialUrl) : url(initialUrl), title("New Tab"), isLoading(true) {
        updateLastAccessed();
    }

    void updateLastAccessed() {
        lastAccessed = std::chrono::system_clock::now();
    }

    void setUrl(const std::string& newUrl) {
        url = newUrl;
        isLoading = true;
        updateLastAccessed();
    }

    void setTitle(const std::string& newTitle) {
        title = newTitle;
    }

    void finishLoading() {
        isLoading = false;
    }

    std::string getUrl() const { return url; }
    std::string getTitle() const { return title; }
    bool getIsLoading() const { return isLoading; }
    std::chrono::system_clock::time_point getLastAccessed() const { return lastAccessed; }
};

// WebBrowser class to manage multiple tabs
class WebBrowser {
private:
    std::vector<std::unique_ptr<Tab>> tabs;
    std::atomic<size_t> activeTabIndex;
    std::mutex tabsMutex;

    // Maximum number of tabs allowed
    static constexpr size_t MAX_TABS = 100;

public:
    WebBrowser() : activeTabIndex(0) {}

    // Add a new tab to the browser
    bool addTab(const std::string& url) {
        std::lock_guard<std::mutex> lock(tabsMutex);

        if (tabs.size() >= MAX_TABS) {
            std::cerr << "Error: Maximum number of tabs reached." << std::endl;
            return false;
        }

        try {
            tabs.push_back(std::make_unique<Tab>(url));
            std::cout << "New tab added with URL: " << url << std::endl;
            return true;
        } catch (const std::bad_alloc& e) {
            std::cerr << "Error: Memory allocation failed when adding a new tab." << std::endl;
            return false;
        }
    }

    // Remove a tab from the browser
    bool removeTab(size_t index) {
        std::lock_guard<std::mutex> lock(tabsMutex);

        if (index >= tabs.size()) {
            std::cerr << "Error: Invalid tab index." << std::endl;
            return false;
        }

        tabs.erase(tabs.begin() + index);
        if (activeTabIndex >= tabs.size()) {
            activeTabIndex = tabs.size() - 1;
        }

        std::cout << "Tab removed at index: " << index << std::endl;
        return true;
    }

    // Switch to a different tab
    bool switchTab(size_t index) {
        if (index >= tabs.size()) {
            std::cerr << "Error: Invalid tab index." << std::endl;
            return false;
        }

        activeTabIndex = index;
        tabs[index]->updateLastAccessed();
        std::cout << "Switched to tab: " << tabs[index]->getTitle() << std::endl;
        return true;
    }

    // Get the number of open tabs
    size_t getTabCount() const {
        return tabs.size();
    }

    // Get the index of the active tab
    size_t getActiveTabIndex() const {
        return activeTabIndex;
    }

    // Print information about all open tabs
    void printTabInfo() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(tabsMutex));

        std::cout << "Open tabs:" << std::endl;
        for (size_t i = 0; i < tabs.size(); ++i) {
            std::cout << (i == activeTabIndex ? "* " : "  ") << i << ": " << tabs[i]->getTitle()
                      << " (" << tabs[i]->getUrl() << ")" << std::endl;
        }
    }};

// Function to simulate loading a web page
void simulatePageLoad(Tab& tab) {
    std::cout << "Loading " << tab.getUrl() << "..." << std::endl;
    
    // Simulate network delay
    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 2000 + 1000));
    
    tab.setTitle("Page Title for " + tab.getUrl());
    tab.finishLoading();
    std::cout << "Finished loading " << tab.getUrl() << std::endl;
}

// Main function to demonstrate the usage of the WebBrowser class
int main() {
    srand(static_cast<unsigned int>(time(nullptr)));

    WebBrowser browser;

    // Add some initial tabs
    browser.addTab("https://www.Aluminum.com");
    browser.addTab("https://www.github.com");
    browser.addTab("https://www.stackoverflow.com");

    // Print initial tab information
    browser.printTabInfo();

    // Simulate user interactions
    for (int i = 0; i < 5; ++i) {
        std::cout << "\nSimulating user interaction " << i + 1 << ":" << std::endl;

        // Randomly choose an action: add tab, remove tab, or switch tab
        int action = rand() % 3;

        switch (action) {
            case 0: // Add tab
                {
                    std::string url = "https://www.random" + std::to_string(rand() % 1000) + ".com";
                    if (browser.addTab(url)) {
                        size_t newTabIndex = browser.getTabCount() - 1;
                    }
                }
                break;
            case 1: // Remove tab
                if (browser.getTabCount() > 1) {
                    size_t indexToRemove = rand() % browser.getTabCount();
                    browser.removeTab(indexToRemove);
                }
                break;
            case 2: // Switch tab
                {
                    size_t newIndex = rand() % browser.getTabCount();
                    browser.switchTab(newIndex);
                }
                break;
        }

        // Print updated tab information
        browser.printTabInfo();

        // Small delay between actions
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    std::cout << "\nFinal tab state:" << std::endl;
    browser.printTabInfo();

    return 0;
}