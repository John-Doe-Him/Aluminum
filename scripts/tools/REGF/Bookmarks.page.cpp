
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <regex>
#include <map>
#include <memory>
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#include <cctype>

// Aluminum Browser Bookmark Utility
// Version: 1.0
// Author: Aluminum Development Team
// Last Updated: 2023-06-15

// Forward declarations
class Bookmark;
class BookmarkManager;
class BookmarkExporter;
class BookmarkImporter;

// Bookmark class to represent individual bookmarks
class Bookmark {
private:
    std::string title;
    std::string url;
    std::string description;
    std::time_t creationDate;
    std::time_t lastVisited;
    int visitCount;

public:
    Bookmark(const std::string& t, const std::string& u, const std::string& d = "")
        : title(t), url(u), description(d), creationDate(std::time(nullptr)),
          lastVisited(std::time(nullptr)), visitCount(0) {}

    // Getters
    std::string getTitle() const { return title; }
    std::string getURL() const { return url; }
    std::string getDescription() const { return description; }
    std::time_t getCreationDate() const { return creationDate; }
    std::time_t getLastVisited() const { return lastVisited; }
    int getVisitCount() const { return visitCount; }

    // Setters
    void setTitle(const std::string& t) { title = t; }
    void setURL(const std::string& u) { url = u; }
    void setDescription(const std::string& d) { description = d; }

    // Update last visited time and increment visit count
    void updateVisit() {
        lastVisited = std::time(nullptr);
        ++visitCount;
    }

    // Serialize bookmark to string
    std::string serialize() const {
        std::stringstream ss;
        ss << title << "|" << url << "|" << description << "|"
           << creationDate << "|" << lastVisited << "|" << visitCount;
        return ss.str();
    }

    // Deserialize string to bookmark
    static Bookmark deserialize(const std::string& data) {
        std::stringstream ss(data);
        std::string title, url, description;
        std::time_t creationDate, lastVisited;
        int visitCount;

        std::getline(ss, title, '|');
        std::getline(ss, url, '|');
        std::getline(ss, description, '|');
        ss >> creationDate;
        ss.ignore();
        ss >> lastVisited;
        ss.ignore();
        ss >> visitCount;

        Bookmark bookmark(title, url, description);
        bookmark.creationDate = creationDate;
        bookmark.lastVisited = lastVisited;
        bookmark.visitCount = visitCount;

        return bookmark;
    }
};

// BookmarkManager class to manage bookmarks
class BookmarkManager {
private:
    std::vector<Bookmark> bookmarks;
    std::string dataFilePath;

    // Helper function to save bookmarks to file
    void saveToFile() const {
        std::ofstream file(dataFilePath);
        if (!file) {
            throw std::runtime_error("Unable to open file for writing: " + dataFilePath);
        }

        for (const auto& bookmark : bookmarks) {
            file << bookmark.serialize() << std::endl;
        }
    }

    // Helper function to load bookmarks from file
    void loadFromFile() {
        std::ifstream file(dataFilePath);
        if (!file) {
            // If file doesn't exist, create an empty one
            std::ofstream newFile(dataFilePath);
            return;
        }

        bookmarks.clear();
        std::string line;
        while (std::getline(file, line)) {
            bookmarks.push_back(Bookmark::deserialize(line));
        }
    }

public:
    BookmarkManager(const std::string& filePath) : dataFilePath(filePath) {
        loadFromFile();
    }

    // Add a new bookmark
    void addBookmark(const Bookmark& bookmark) {
        bookmarks.push_back(bookmark);
        saveToFile();
    }

    // Remove a bookmark by URL
    void removeBookmark(const std::string& url) {
        auto it = std::remove_if(bookmarks.begin(), bookmarks.end(),
                                 [&url](const Bookmark& b) { return b.getURL() == url; });
        if (it != bookmarks.end()) {
            bookmarks.erase(it, bookmarks.end());
            saveToFile();
        }
    }

    // Update an existing bookmark
    void updateBookmark(const std::string& url, const Bookmark& updatedBookmark) {
        auto it = std::find_if(bookmarks.begin(), bookmarks.end(),
                               [&url](const Bookmark& b) { return b.getURL() == url; });
        if (it != bookmarks.end()) {
            *it = updatedBookmark;
            saveToFile();
        }
    }

    // Get all bookmarks
    std::vector<Bookmark> getAllBookmarks() const {
        return bookmarks;
    }

    // Search bookmarks by title or URL
    std::vector<Bookmark> searchBookmarks(const std::string& query) const {
        std::vector<Bookmark> results;
        std::regex pattern(query, std::regex_constants::icase);

        for (const auto& bookmark : bookmarks) {
            if (std::regex_search(bookmark.getTitle(), pattern) ||
                std::regex_search(bookmark.getURL(), pattern)) {
                results.push_back(bookmark);
            }
        }

        return results;
    }

    // Sort bookmarks by various criteria
    void sortBookmarks(const std::string& criteria) {
        if (criteria == "title") {
            std::sort(bookmarks.begin(), bookmarks.end(),
                      [](const Bookmark& a, const Bookmark& b) {
                          return a.getTitle() < b.getTitle();
                      });
        } else if (criteria == "url") {
            std::sort(bookmarks.begin(), bookmarks.end(),
                      [](const Bookmark& a, const Bookmark& b) {
                          return a.getURL() < b.getURL();
                      });
        } else if (criteria == "date") {
            std::sort(bookmarks.begin(), bookmarks.end(),
                      [](const Bookmark& a, const Bookmark& b) {
                          return a.getCreationDate() > b.getCreationDate();
                      });
        } else if (criteria == "visits") {
            std::sort(bookmarks.begin(), bookmarks.end(),
                      [](const Bookmark& a, const Bookmark& b) {
                          return a.getVisitCount() > b.getVisitCount();
                      });
        }
        saveToFile();
    }
};

// BookmarkExporter class to export bookmarks in various formats
class BookmarkExporter {
public:
    static void exportToHTML(const std::vector<Bookmark>& bookmarks, const std::string& filePath) {
        std::ofstream file(filePath);
        if (!file) {
            throw std::runtime_error("Unable to open file for writing: " + filePath);
        }

        file << "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n"
             << "<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n"
             << "<TITLE>Bookmarks</TITLE>\n"
             << "<H1>Bookmarks</H1>\n"
             << "<DL><p>\n";

        for (const auto& bookmark : bookmarks) {
            file << "    <DT><A HREF=\"" << bookmark.getURL() << "\" ADD_DATE=\""
                 << bookmark.getCreationDate() << "\">" << bookmark.getTitle() << "</A>\n";
            if (!bookmark.getDescription().empty()) {
                file << "    <DD>" << bookmark.getDescription() << "\n";
            }
        }

        file << "</DL><p>\n";
    }

    static void exportToCSV(const std::vector<Bookmark>& bookmarks, const std::string& filePath) {
        std::ofstream file(filePath);
        if (!file) {
            throw std::runtime_error("Unable to open file for writing: " + filePath);
        }

        file << "Title,URL,Description,Creation Date,Last Visited,Visit Count\n";

        for (const auto& bookmark : bookmarks) {
            file << "\"" << bookmark.getTitle() << "\","
                 << "\"" << bookmark.getURL() << "\","
                 << "\"" << bookmark.getDescription() << "\","
                 << bookmark.getCreationDate() << ","
                 << bookmark.getLastVisited() << ","
                 << bookmark.getVisitCount() << "\n";
        }
    }

    static void exportToJSON(const std::vector<Bookmark>& bookmarks, const std::string& filePath) {
        std::ofstream file(filePath);
        if (!file) {
            throw std::runtime_error("Unable to open file for writing: " + filePath);
        }

        file << "{\n  \"bookmarks\": [\n";

        for (size_t i = 0; i < bookmarks.size(); ++i) {
            const auto& bookmark = bookmarks[i];
            file << "    {\n"
                 << "      \"title\": \"" << bookmark.getTitle() << "\",\n"
                 << "      \"url\": \"" << bookmark.getURL() << "\",\n"
                 << "      \"description\": \"" << bookmark.getDescription() << "\",\n"
                 << "      \"creationDate\": " << bookmark.getCreationDate() << ",\n"
                 << "      \"lastVisited\": " << bookmark.getLastVisited() << ",\n"
                 << "      \"visitCount\": " << bookmark.getVisitCount() << "\n"
                 << "    }" << (i < bookmarks.size() - 1 ? "," : "") << "\n";
        }

        file << "  ]\n}\n";
    }
};

// BookmarkImporter class to import bookmarks from various formats
class BookmarkImporter {
public:
    static std::vector<Bookmark> importFromHTML(const std::string& filePath) {
        std::vector<Bookmark> bookmarks;
        std::ifstream file(filePath);
        if (!file) {
            throw std::runtime_error("Unable to open file for reading: " + filePath);
        }

        std::string line;
        std::regex linkPattern("<A HREF=\"([^\"]*)\"[^>]*>([^<]*)</A>");
        std::smatch matches;

        while (std::getline(file, line)) {
            if (std::regex_search(line, matches, linkPattern)) {
                std::string url = matches[1];
                std::string title = matches[2];
                bookmarks.emplace_back(title, url);
            }
        }

        return bookmarks;
    }

    static std::vector<Bookmark> importFromCSV(const std::string& filePath) {
        std::vector<Bookmark> bookmarks;
        std::ifstream file(filePath);
        if (!file) {
            throw std::runtime_error("Unable to open file for reading: " + filePath);
        }

        std::string line;
        std::getline(file, line); // Skip header

        while (std::getline(file, line)) {
            std::stringstream ss(line);
            std::string title, url, description;
            std::time_t creationDate, lastVisited;
            int visitCount;

            std::getline(ss, title, ',');
            std::getline(ss, url, ',');
            std::getline(ss, description, ',');
            ss >> creationDate;
            ss.ignore();
            ss >> lastVisited;
            ss.ignore();
            ss >> visitCount;

            Bookmark bookmark(title, url, description);
            bookmark.updateVisit(); // Set last visited and visit count
            bookmarks.push_back(bookmark);
        }

        return bookmarks;
    }
};

// Main function to demonstrate the bookmark utility
int main() {
    std::cout << "Aluminum Browser Bookmark Utility" << std::endl;
    std::cout << "=================================" << std::endl;

    // Initialize BookmarkManager
    BookmarkManager manager("bookmarks.dat");

    // Main loop
    while (true) {
        std::cout << "\nChoose an option:" << std::endl;
        std::cout << "1. Add bookmark" << std::endl;
        std::cout << "2. Remove bookmark" << std::endl;
        std::cout << "3. Update bookmark" << std::endl;
        std::cout << "4. List all bookmarks" << std::endl;
        std::cout << "5. Search bookmarks" << std::endl;
        std::cout << "6. Sort bookmarks" << std::endl;
        std::cout << "7. Export bookmarks" << std::endl;
        std::cout << "8. Import bookmarks" << std::endl;
        std::cout << "9. Exit" << std::endl;

        int choice;
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
            case 1: {
                std::string title, url, description;
                std::cout << "Enter title: ";
                std::getline(std::cin, title);
                std::cout << "Enter URL: ";
                std::getline(std::cin, url);
                std::cout << "Enter description (optional): ";
                std::getline(std::cin, description);
                manager.addBookmark(Bookmark(title, url, description));
                std::cout << "Bookmark added successfully." << std::endl;
                break;
            }
            case 2: {
                std::string url;
                std::cout << "Enter URL of bookmark to remove: ";
                std::getline(std::cin, url);
                manager.removeBookmark(url);
                std::cout << "Bookmark removed successfully." << std::endl;
                break;
            }
            case 3: {
                std::string url, newTitle, newUrl, newDescription;
                std::cout << "Enter URL of bookmark to update: ";
                std::getline(std::cin, url);
                std::cout << "Enter new title: ";
                std::getline(std::cin, newTitle);
                std::cout << "Enter new URL: ";
                std::getline(std::cin, newUrl);
                std::cout << "Enter new description (optional): ";
                std::getline(std::cin, newDescription);
                manager.updateBookmark(url, Bookmark(newTitle, newUrl, newDescription));
                std::cout << "Bookmark updated successfully." << std::endl;
                break;
            }
            case 4: {
                auto bookmarks = manager.getAllBookmarks();
                std::cout << "All bookmarks:" << std::endl;
                for (const auto& bookmark : bookmarks) {
                    std::cout << "Title: " << bookmark.getTitle() << std::endl;
                    std::cout << "URL: " << bookmark.getURL() << std::endl;
                    std::cout << "Description: " << bookmark.getDescription() << std::endl;
                    std::cout << std::endl;
                }
                break;
            }}}