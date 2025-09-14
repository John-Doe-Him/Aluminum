
# Unit Test Runner for Aluminum Web Browser
# This script runs unit tests for the Aluminum web browser on a monthly basis
# It includes comprehensive error handling, logging, and reporting features

require 'date'
require 'logger'
require 'fileutils'
require 'net/smtp'
require 'yaml'

class AluminumUnitTestRunner
  attr_reader :logger, :config

  def initialize
    @logger = setup_logger
    @config = load_configuration
  end

  def run
    logger.info("Starting Aluminum unit test run at #{Time.now}")

    if should_run_tests?
      setup_test_environment
      run_unit_tests
      generate_report
      cleanup_test_environment
      send_email_notification
    else
      logger.info("Skipping test run. Not the scheduled day for monthly tests.")
    end

    logger.info("Aluminum unit test run completed at #{Time.now}")
  end

  private

  def setup_logger
    logger = Logger.new(File.join(Dir.pwd, 'logs', 'aluminum_unit_tests.log'), 'monthly')
    logger.level = Logger::INFO
    logger.formatter = proc do |severity, datetime, progname, msg|
      "[#{datetime}] #{severity}: #{msg}\n"
    end
    logger
  end

  def load_configuration
    config_file = File.join(Dir.pwd, 'config', 'aluminum_test_config.yml')
    YAML.load_file(config_file)
  rescue StandardError => e
    logger.error("Failed to load configuration: #{e.message}")
    exit(1)
  end

  def should_run_tests?
    today = Date.today
    scheduled_day = config['scheduled_day'] || 1
    today.day == scheduled_day
  end

  def setup_test_environment
    logger.info("Setting up test environment")
    
    # Create temporary test directory
    @test_dir = File.join(Dir.pwd, 'tmp', "aluminum_tests_#{Time.now.strftime('%Y%m%d_%H%M%S')}")
    FileUtils.mkdir_p(@test_dir)
    
    # Clone the latest version of the Aluminum repository
    clone_repository
    
    # Install dependencies
    install_dependencies
    
    # Set up test database
    setup_test_database
  rescue StandardError => e
    logger.error("Failed to set up test environment: #{e.message}")
    cleanup_test_environment
    exit(1)
  end

  def clone_repository
    logger.info("Cloning Aluminum repository")
    repo_url = config['repository_url']
    system("git clone #{repo_url} #{@test_dir}")
    Dir.chdir(@test_dir)
  end

  def install_dependencies
    logger.info("Installing dependencies")
    system("npm install")
  end

  def setup_test_database
    logger.info("Setting up test database")
    system("npm run db:setup")
  end

  def run_unit_tests
    logger.info("Running unit tests")
    
    test_command = config['test_command'] || "npm run test"
    test_output = `#{test_command}`
    
    if $?.success?
      logger.info("Unit tests completed successfully")
      @test_results = parse_test_results(test_output)
    else
      logger.error("Unit tests failed")
      @test_results = { status: 'failed', output: test_output }
    end
  rescue StandardError => e
    logger.error("Error running unit tests: #{e.message}")
    @test_results = { status: 'error', message: e.message }
  end

  def parse_test_results(output)
    
    {
      status: 'success',
      total_tests: output.scan(/(\d+) tests/).first&.first.to_i,
      passed_tests: output.scan(/(\d+) passing/).first&.first.to_i,
      failed_tests: output.scan(/(\d+) failing/).first&.first.to_i,
      duration: output.scan(/(\d+\.\d+)s/).first&.first.to_f
    }
  end

  def generate_report
    logger.info("Generating test report")
    
    report = <<~REPORT
      Aluminum Unit Test Report
      -------------------------
      Date: #{Date.today}
      Status: #{@test_results[:status]}
      Total Tests: #{@test_results[:total_tests]}
      Passed Tests: #{@test_results[:passed_tests]}
      Failed Tests: #{@test_results[:failed_tests]}
      Duration: #{@test_results[:duration]} seconds
      
      Detailed Results:
      #{@test_results[:output]}
    REPORT
    
    report_file = File.join(@test_dir, 'test_report.txt')
    File.write(report_file, report)
    
    logger.info("Test report generated: #{report_file}")
    @report_file = report_file
  rescue StandardError => e
    logger.error("Failed to generate test report: #{e.message}")
  end

  def cleanup_test_environment
    logger.info("Cleaning up test environment")
    
    Dir.chdir(File.expand_path('..', @test_dir))
    FileUtils.rm_rf(@test_dir)
    
    logger.info("Test environment cleaned up")
  rescue StandardError => e
    logger.error("Failed to clean up test environment: #{e.message}")
  end

  def send_email_notification
    logger.info("Sending email notification")
    
    from_address = config['email']['from']
    to_address = config['email']['to']
    smtp_server = config['email']['smtp_server']
    smtp_port = config['email']['smtp_port']
    
    message = <<~MESSAGE
      From: Aluminum Test Runner <#{from_address}>
      To: Aluminum Development Team <#{to_address}>
      Subject: Aluminum Unit Test Results - #{Date.today}
      
      #{File.read(@report_file)}
    MESSAGE
    
    Net::SMTP.start(smtp_server, smtp_port) do |smtp|
      smtp.send_message message, from_address, to_address
    end
    
    logger.info("Email notification sent")
  rescue StandardError => e
    logger.error("Failed to send email notification: #{e.message}")
  end
end

# Run the Aluminum unit tests
AluminumUnitTestRunner.new.run
