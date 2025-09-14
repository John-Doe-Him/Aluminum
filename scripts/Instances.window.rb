# Initialize and create dense browser window instances

# Import necessary libraries
require 'selenium-webdriver'
require 'capybara'
require 'capybara/dsl'
require 'capybara/selenium/driver'
require 'nokogiri'
require 'uri'
require 'net/http'
require 'json'
require 'logger'

# Configure Capybara
Capybara.default_driver = :selenium_chrome
Capybara.javascript_driver = :selenium_chrome
Capybara.run_server = false
Capybara.default_max_wait_time = 10

# Create a logger for debugging
logger = Logger.new(STDOUT)
logger.level = Logger::INFO

# Define a class for managing browser instances
class BrowserInstanceManager
  include Capybara::DSL

  def initialize(num_instances)
    @num_instances = num_instances
    @instances = []
    @current_instance = 0
    initialize_instances
  end

  private

  def initialize_instances
    @num_instances.times do |i|
      logger.info("Initializing browser instance #{i + 1}")
      @instances << create_browser_instance
    end
  end

  def create_browser_instance
    options = Selenium::WebDriver::Chrome::Options.new
    options.add_argument('--headless') # Run in headless mode (optional)
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--window-size=1920,1080')
    
    # Add more Chrome options as needed
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-popup-blocking')
    options.add_argument('--disable-infobars')
    
    # Set up custom preferences
    prefs = {
      'profile.default_content_setting_values.notifications' => 2,
      'profile.default_content_setting_values.geolocation' => 2,
      'download.default_directory' => Dir.pwd + '/downloads'
    }
    options.add_preference(:prefs, prefs)
    
    # Create and return the Capybara session
    Capybara::Session.new(:selenium_chrome, options: options)
  end

  public

  def with_instance
    instance = @instances[@current_instance]
    @current_instance = (@current_instance + 1) % @num_instances
    yield instance if block_given?
  end

  def execute_on_all_instances
    @instances.each do |instance|
      yield instance if block_given?
    end
  end

  def close_all_instances
    @instances.each do |instance|
      instance.driver.quit
    end
    @instances.clear
  end
end

# Usage example
num_browser_instances = 5
browser_manager = BrowserInstanceManager.new(num_browser_instances)

# Example of using a single instance
browser_manager.with_instance do |browser|
  logger.info("Navigating to example.com")
  browser.visit('https://example.com')
  logger.info("Current URL: #{browser.current_url}")
end

# Example of executing an action on all instances
browser_manager.execute_on_all_instances do |browser|
  logger.info("Checking title on all instances")
  puts "Title: #{browser.title}"
end

# Complex interaction example
browser_manager.with_instance do |browser|
  logger.info("Performing complex interaction")
  browser.visit('https://example.com/login')
  
  if browser.has_field?('username') && browser.has_field?('password')
    browser.fill_in 'username', with: 'testuser'
    browser.fill_in 'password', with: 'securepassword'
    browser.click_button 'Login'
    
    logger.info("Waiting for dashboard to load")
    browser.has_css?('.dashboard', wait: 15)
    
    if browser.has_content?('Welcome, Test User')
      logger.info("Successfully logged in")
    else
      logger.error("Login failed or unexpected content")
    end
  else
    logger.warn("Login form not found on the page")
  end
end

# Example of handling AJAX requests
browser_manager.with_instance do |browser|
  logger.info("Handling AJAX request")
  browser.visit('https://example.com/ajax-page')
  
  browser.execute_script("$.ajax({url: '/api/data', success: function(result) { $('#result').html(result); }})")
  
  browser.has_css?('#result', wait: 10)
  result_text = browser.find('#result').text
  logger.info("AJAX result: #{result_text}")
end

# Example of taking screenshots
browser_manager.execute_on_all_instances do |browser|
  logger.info("Taking screenshots of all instances")
  browser.visit('https://example.com')
  screenshot = browser.save_screenshot("screenshot_#{Time.now.to_i}.png")
  logger.info("Screenshot saved: #{screenshot}")
end

# Example of handling iframes
browser_manager.with_instance do |browser|
  logger.info("Interacting with iframes")
  browser.visit('https://example.com/page-with-iframe')
  
  browser.within_frame('iframe-name') do
    browser.fill_in 'search', with: 'Capybara'
    browser.click_button 'Search'
    logger.info("Search results: #{browser.all('.result').map(&:text)}")
  end
end

# Example of handling multiple windows/tabs
browser_manager.with_instance do |browser|
  logger.info("Handling multiple windows")
  browser.visit('https://example.com')
  
  browser.execute_script("window.open('https://example.org', '_blank')")
  browser.switch_to_window(browser.windows.last)
  
  logger.info("New window URL: #{browser.current_url}")
  
  browser.switch_to_window(browser.windows.first)
  logger.info("Switched back to original window")
end

# Example of custom wait conditions
browser_manager.with_instance do |browser|
  logger.info("Using custom wait conditions")
  browser.visit('https://example.com/dynamic-content')
  
  custom_wait = Selenium::WebDriver::Wait.new(timeout: 20, interval: 1)
  custom_wait.until { browser.evaluate_script('return document.readyState') == 'complete' }
  
  element = custom_wait.until { browser.find('#dynamic-element') }
  logger.info("Dynamic element text: #{element.text}")
end

# Clean up resources
logger.info("Closing all browser instances")
browser_manager.close_all_instances
