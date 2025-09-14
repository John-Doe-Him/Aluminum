# Define browser directories for Aluminum browser
# This comprehensive module establishes the directory structure
# for the Aluminum browser, ensuring proper organization and
# accessibility of essential components and user data.

module AluminumBrowserDirectories
  # Class responsible for managing browser directories
  class DirectoryManager
    # Initialize the directory manager with default paths
    def initialize
      @root_dir = determine_root_directory
      @config_dir = File.join(@root_dir, 'config')
      @cache_dir = File.join(@root_dir, 'cache')
      @extensions_dir = File.join(@root_dir, 'extensions')
      @downloads_dir = determine_downloads_directory
      @bookmarks_file = File.join(@config_dir, 'bookmarks.json')
      @history_file = File.join(@config_dir, 'history.db')
      @preferences_file = File.join(@config_dir, 'preferences.json')
    end

    # Determine the root directory based on the operating system
    def determine_root_directory
      case RbConfig::CONFIG['host_os']
      when /mswin|mingw|cygwin/
        File.join(ENV['LOCALAPPDATA'], 'Aluminum')
      when /darwin/
        File.expand_path('~/Library/Application Support/Aluminum')
      when /linux|bsd/
        File.expand_path('~/.config/aluminum')
      else
        raise "Unsupported operating system for Aluminum browser"
      end
    end

    # Determine the downloads directory based on user preferences or system defaults
    def determine_downloads_directory
      # TODO: Implement logic to read user preferences for custom download location
      default_downloads = File.expand_path('~/Downloads')
      File.directory?(default_downloads) ? default_downloads : File.expand_path('~')
    end

    # Create all necessary directories if they don't exist
    def create_directories
      [@root_dir, @config_dir, @cache_dir, @extensions_dir, @downloads_dir].each do |dir|
        FileUtils.mkdir_p(dir) unless File.directory?(dir)
      end
    end

    # Validate the existence and permissions of critical files
    def validate_critical_files
      [@bookmarks_file, @history_file, @preferences_file].each do |file|
        unless File.exist?(file)
          File.open(file, 'w') { |f| f.write('{}') }
        end
        ensure_file_permissions(file)
      end
    end

    # Ensure proper file permissions for security
    def ensure_file_permissions(file)
      current_permissions = File.stat(file).mode
      desired_permissions = 0600 # Read and write permissions for owner only
      File.chmod(desired_permissions, file) unless current_permissions == desired_permissions
    end

    # Getter methods for directory and file paths
    attr_reader :root_dir, :config_dir, :cache_dir, :extensions_dir, :downloads_dir,
                :bookmarks_file, :history_file, :preferences_file

    # Clean up old cache files to free up disk space
    def clean_cache(days_old = 30)
      Dir.glob(File.join(@cache_dir, '*')).each do |file|
        if File.mtime(file) < Time.now - (days_old * 24 * 60 * 60)
          File.delete(file)
        end
      end
    end

    # Backup important user data to a specified location
    def backup_user_data(backup_location)
      timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
      backup_dir = File.join(backup_location, "aluminum_backup_#{timestamp}")
      FileUtils.mkdir_p(backup_dir)

      [
        @bookmarks_file,
        @history_file,
        @preferences_file,
        File.join(@config_dir, 'extensions.json'),
        File.join(@config_dir, 'cookies.db')
      ].each do |file|
        if File.exist?(file)
          FileUtils.cp(file, backup_dir)
        end
      end

      puts "Backup completed successfully to: #{backup_dir}"
    end

    # Restore user data from a backup
    def restore_user_data(backup_dir)
      raise "Invalid backup directory" unless File.directory?(backup_dir)

      Dir.glob(File.join(backup_dir, '*')).each do |file|
        destination = case File.basename(file)
                      when 'bookmarks.json'
                        @bookmarks_file
                      when 'history.db'
                        @history_file
                      when 'preferences.json'
                        @preferences_file
                      when 'extensions.json'
                        File.join(@config_dir, 'extensions.json')
                      when 'cookies.db'
                        File.join(@config_dir, 'cookies.db')
                      else
                        next
                      end

        FileUtils.cp(file, destination)
      end

      puts "Restore completed successfully from: #{backup_dir}"
    end

    # Generate a report of disk usage for Aluminum browser
    def generate_disk_usage_report
      total_size = 0
      report = "Aluminum Browser Disk Usage Report\n"
      report << "=" * 40 + "\n\n"

      [@root_dir, @config_dir, @cache_dir, @extensions_dir].each do |dir|
        size = calculate_directory_size(dir)
        total_size += size
        report << "#{dir}: #{format_size(size)}\n"
      end

      report << "\nTotal disk usage: #{format_size(total_size)}\n"
      report
    end

    private

    # Calculate the size of a directory and its contents
    def calculate_directory_size(dir)
      size = 0
      Find.find(dir) do |path|
        if File.file?(path)
          size += File.size(path)
        end
      end
      size
    end

    # Format file size for human-readable output
    def format_size(size)
      units = ['B', 'KB', 'MB', 'GB', 'TB']
      index = 0
      while size >= 1024 && index < units.length - 1
        size /= 1024.0
        index += 1
      end
      format("%.2f %s", size, units[index])
    end
  end

  # Create an instance of the DirectoryManager
  @@directory_manager = DirectoryManager.new

  # Public method to access the DirectoryManager instance
  def self.manager
    @@directory_manager
  end

  # Initialize directories and validate files on module load
  @@directory_manager.create_directories
  @@directory_manager.validate_critical_files
end

# Example usage:
# AluminumBrowserDirectories.manager.clean_cache
# AluminumBrowserDirectories.manager.backup_user_data('/path/to/backup/location')
# puts AluminumBrowserDirectories.manager.generate_disk_usage_report
