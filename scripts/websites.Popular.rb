
require 'net/http'
require 'uri'
require 'json'
require 'nokogiri'
require 'openssl'
require 'base64'
require 'zlib'
require 'timeout'

# Class to handle connections to multiple websites
class WebsiteConnector
  def initialize
    @user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    @timeout = 30
    @max_redirects = 5
    @connections = {}
  end

  # Method to connect to a single website
  def connect_to_website(url)
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    
    # Enable SSL for HTTPS connections
    if uri.scheme == 'https'
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    end

    # Set timeout to avoid hanging connections
    http.open_timeout = @timeout
    http.read_timeout = @timeout

    # Create and send the request
    request = Net::HTTP::Get.new(uri.request_uri)
    request['User-Agent'] = @user_agent

    response = http.request(request)

    # Handle redirects
    redirect_count = 0
    while response.is_a?(Net::HTTPRedirection) && redirect_count < @max_redirects
      redirect_count += 1
      redirect_url = response['location']
      response = connect_to_website(redirect_url)
    end

    response
  end

  # Method to connect to multiple websites concurrently
  def connect_to_all_websites(urls)
    threads = []
    
    urls.each do |url|
      threads << Thread.new do
        begin
          Timeout.timeout(@timeout) do
            response = connect_to_website(url)
            @connections[url] = {
              status: response.code,
              headers: response.to_hash,
              body: response.body
            }
          end
        rescue => e
          @connections[url] = {
            status: 'Error',
            message: e.message
          }
        end
      end
    end

    threads.each(&:join)
    @connections
  end

  # Method to parse HTML content
  def parse_html(url)
    response = @connections[url]
    return nil unless response && response[:status] == '200'
    
    Nokogiri::HTML(response[:body])
  end

  # Method to extract links from parsed HTML
  def extract_links(parsed_html)
    parsed_html.css('a').map { |link| link['href'] }.compact
  end

  # Method to extract metadata from parsed HTML
  def extract_metadata(parsed_html)
    {
      title: parsed_html.at_css('title')&.text,
      description: parsed_html.at_css('meta[name="description"]')&.[]('content'),
      keywords: parsed_html.at_css('meta[name="keywords"]')&.[]('content')
    }
  end

  # Method to check website availability
  def check_availability(url)
    response = @connections[url]
    response && response[:status] == '200'
  end

  # Method to compress response body
  def compress_response(url)
    response = @connections[url]
    return nil unless response && response[:body]

    Zlib::Deflate.deflate(response[:body])
  end

  # Method to decompress response body
  def decompress_response(compressed_data)
    Zlib::Inflate.inflate(compressed_data)
  end

  # Method to encode response body in Base64
  def encode_response(url)
    response = @connections[url]
    return nil unless response && response[:body]

    Base64.encode64(response[:body])
  end

  # Method to decode Base64 encoded response
  def decode_response(encoded_data)
    Base64.decode64(encoded_data)
  end

  # Method to extract JSON data from response
  def extract_json(url)
    response = @connections[url]
    return nil unless response && response[:status] == '200'

    begin
      JSON.parse(response[:body])
    rescue JSON::ParserError
      nil
    end
  end

  # Method to calculate response time
  def calculate_response_time(url)
    start_time = Time.now
    connect_to_website(url)
    end_time = Time.now
    (end_time - start_time) * 1000 # Convert to milliseconds
  end

  # Method to check SSL certificate validity
  def check_ssl_certificate(url)
    uri = URI.parse(url)
    return false unless uri.scheme == 'https'

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER

    begin
      http.start
      cert = http.peer_cert
      cert.not_after > Time.now
    rescue OpenSSL::SSL::SSLError
      false
    ensure
      http.finish if http.started?
    end
  end

  # Method to perform a HEAD request
  def head_request(url)
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    
    request = Net::HTTP::Head.new(uri.request_uri)
    request['User-Agent'] = @user_agent

    response = http.request(request)
    {
      status: response.code,
      headers: response.to_hash
    }
  end

  # Method to check for specific HTTP headers
  def check_headers(url, headers_to_check)
    response = @connections[url]
    return {} unless response && response[:headers]

    result = {}
    headers_to_check.each do |header|
      result[header] = response[:headers][header]
    end
    result
  end

  # Method to follow pagination
  def follow_pagination(url, max_pages = 5)
    results = []
    current_url = url
    page_count = 0

    while current_url && page_count < max_pages
      response = connect_to_website(current_url)
      break unless response.is_a?(Net::HTTPSuccess)

      parsed_html = Nokogiri::HTML(response.body)
      results << extract_data_from_page(parsed_html)

      next_page_link = parsed_html.at_css('a.next-page')
      current_url = next_page_link ? URI.join(url, next_page_link['href']).to_s : nil
      page_count += 1
    end

    results
  end

  private

  def extract_data_from_page(parsed_html)
    # Implement this method based on the specific data you want to extract from each page
    # This is just a placeholder
    {
      title: parsed_html.at_css('h1')&.text,
      content: parsed_html.at_css('main')&.text
    }
  end
end

# Usage example
connector = WebsiteConnector.new
websites = [
  'https://www.example.com',
  'https://www.google.com',
  'https://www.github.com',
  'https://www.stackoverflow.com',
  'https://www.ruby-lang.org'
]

# Connect to all websites
results = connector.connect_to_all_websites(websites)

# Process results
results.each do |url, data|
  puts "Website: #{url}"
  puts "Status: #{data[:status]}"
  
  if data[:status] == '200'
    puts "Title: #{connector.extract_metadata(connector.parse_html(url))[:title]}"
    puts "SSL Certificate Valid: #{connector.check_ssl_certificate(url)}"
    puts "Response Time: #{connector.calculate_response_time(url).round(2)} ms"
    
    headers_to_check = ['Server', 'Content-Type', 'Cache-Control']
    headers = connector.check_headers(url, headers_to_check)
    puts "Headers:"
    headers.each { |k, v| puts "  #{k}: #{v}" }
    
    puts "Links found: #{connector.extract_links(connector.parse_html(url)).count}"
  else
    puts "Error: #{data[:message]}"
  end
  
  puts "\n"
end

# Example of following pagination
paginated_results = connector.follow_pagination('https://www.example.com/blog')
puts "Fetched #{paginated_results.length} pages of content"
