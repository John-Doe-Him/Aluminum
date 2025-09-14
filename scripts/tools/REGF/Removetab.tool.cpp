
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cctype>
#include <stdexcept>

// Aluminum Browser Tab Management System
// Version: 1.0.0
// Author: Karim Sar
// Date: 2023-05-30

// Constants
const int MAX_TABS = 100;
const int TAB_REMOVAL_DELAY_MS = 500;

// Tab structure
struct Tab {
    std::string url;
    std::string title;
    bool isActive;
    std::chrono::system_clock::time_point lastAccessed;
};

// Browser class
class AluminumBrowser {
private:
    std::vector<Tab> tabs;
    int activeTabIndex;

    // Helper function to generate a random string
    std::string generateRandomString(int length) {
        const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; ++i) {
            result += charset[rand() % (sizeof(charset) - 1)];
        }
        return result;
    }

    // Helper function to simulate tab loading
    void simulateTabLoading() {
        std::cout << "Loading";
        for (int i = 0; i < 3; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            std::cout << ".";
            std::cout.flush();
        }
        std::cout << std::endl;
    }

public:
    AluminumBrowser() : activeTabIndex(-1) {
        std::srand(static_cast<unsigned int>(std::time(nullptr)));
    }

    // Add a new tab
    void addTab(const std::string& url) {
        if (tabs.size() >= MAX_TABS) {
            throw std::runtime_error("Maximum number of tabs reached.");
        }

        Tab newTab;
        newTab.url = url;
        newTab.title = "Loading...";
        newTab.isActive = false;
        newTab.lastAccessed = std::chrono::system_clock::now();

        tabs.push_back(newTab);
        switchToTab(static_cast<int>(tabs.size()) - 1);

        simulateTabLoading();
        tabs.back().title = "Tab " + generateRandomString(8);
    }

    // Switch to a specific tab
    void switchToTab(int index) {
        if (index < 0 || index >= static_cast<int>(tabs.size())) {
            throw std::out_of_range("Invalid tab index.");
        }

        if (activeTabIndex != -1) {
            tabs[activeTabIndex].isActive = false;
        }

        activeTabIndex = index;
        tabs[activeTabIndex].isActive = true;
        tabs[activeTabIndex].lastAccessed = std::chrono::system_clock::now();
    }

    // Remove a tab
    void removeTab(int index) {
        if (index < 0 || index >= static_cast<int>(tabs.size())) {
            throw std::out_of_range("Invalid tab index.");
        }

        std::cout << "Preparing to close tab: " << tabs[index].title << std::endl;

        // Simulate tab removal process
        for (int i = 0; i < 5; ++i) {
            std::cout << "Closing tab" << std::string(i + 1, '.') << "\r";
            std::cout.flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(TAB_REMOVAL_DELAY_MS));
        }
        std::cout << std::endl;

        // Remove the tab
        tabs.erase(tabs.begin() + index);

        // Update active tab index
        if (index == activeTabIndex) {
            activeTabIndex = (index > 0) ? index - 1 : 0;
            if (!tabs.empty()) {
                tabs[activeTabIndex].isActive = true;
            } else {
                activeTabIndex = -1;
            }
        } else if (index < activeTabIndex) {
            --activeTabIndex;
        }

        std::cout << "Tab closed successfully." << std::endl;
    }

    // Display all tabs
    void displayTabs() const {
        std::cout << "Current tabs:" << std::endl;
        for (size_t i = 0; i < tabs.size(); ++i) {
            std::cout << (i == static_cast<size_t>(activeTabIndex) ? "* " : "  ")
                      << i << ": " << tabs[i].title << " (" << tabs[i].url << ")" << std::endl;
        }
    }

    // Get the number of open tabs
    size_t getTabCount() const {
        return tabs.size();
    }
};

// Main function to demonstrate tab removal
int main() {
    AluminumBrowser browser;

    try {
        // Add some sample tabs
        browser.addTab("https://www.Aluminum.com");
        browser.addTab("https://www.google.com");
        browser.addTab("https://www.github.com");

        std::cout << "Initial tab state:" << std::endl;
        browser.displayTabs();

        // Remove a tab
        int tabToRemove;
        std::cout << "\nEnter the index of the tab to remove: ";
        std::cin >> tabToRemove;

        browser.removeTab(tabToRemove);

        std::cout << "\nUpdated tab state:" << std::endl;
        browser.displayTabs();

        std::cout << "\nTotal number of open tabs: " << browser.getTabCount() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
