#!/usr/bin/env ruby
# frozen_string_literal: true

require 'find'
require 'set'
require 'json'

class MatchStringsError < StandardError; end

class Config
  def initialize(patterns:, recursive: false, case_sensitive: false, output_format: :text)
    @patterns = patterns
    @recursive = recursive
    @case_sensitive = case_sensitive
    @output_format = output_format
  end

  attr_reader :patterns, :recursive, :case_sensitive, :output_format

  def flags
    @case_sensitive ? '' : 'i'
  end

  def compile_patterns!
    @compiled = @patterns.map do |pattern|
      begin
        Regexp.new(pattern, flags)
      rescue ArgumentError => e
        raise MatchStringsError, "Invalid pattern: #{e.message}"
      end
    end
  end
end

class FileScanner
  def initialize(config)
    @config = config
    @compiled = []
    @files = Set.new
    @matches = []
  end

  def scan!(directory)
    compile_patterns! if @compiled.empty?
    
    Find.find(directory, recursive: @config.recursive) do |path|
      next unless File.file?(path) && !File.directory?(path)
      
      # Skip binary files and common non-text types
      next if is_binary?(path) || skip_file?(path)
      
      @files << path
    end

    @files.each do |file_path|
      begin
        content = File.read(file_path, encoding: 'UTF-8')
        matches_for_file(file_path, content)
      rescue => e
        warn "Error reading #{file_path}: #{e.message}"
      end
    end
  end

  private

  def is_binary?(path)
    return false if File.size(path) < 1024
    
    chunk = File.read(path, size: 8192)
    # Check for null bytes (simple binary detection)
    chunk.include?("\x00")
  end

  def skip_file?(path)
    SKIP_PATTERNS.any? { |p| path.match?(p) }
  end

  SKIP_PATTERNS = [
    /\.(so|dll|exe|bin)$/,
    /\/\.(git|svn|hg|bzr|npm)\//,
    /\.class$/,
    /\.o$|\.obj$/i,
  ].freeze

  def matches_for_file(file_path, content)
    @compiled.each_with_index do |regex, idx|
      next if regex.nil? || !content.match?(regex)
      
      # Find all matches with positions
      matches = []
      offset = 0
      
      while (match = content.match(regex, offset: offset))
        match_start = match.begin(0) + offset
        match_end = match.end(0) + offset
        
        matches << {
          pattern_index: idx,
          start: match_start,
          end: match_end,
          text: match[0],
          line_number: find_line_number(content, match_start),
          file_path: file_path
        }
        
        offset = match.end(0)
      end
      
      @matches.concat(matches) if matches.any?
    end
  end

  def find_line_number(content, position)
    # Simple line number calculation
    content[0...position].count("\n") + 1
  rescue
    1
  end
end

class OutputFormatter
  def initialize(matches:, config:)
    @matches = matches
    @config = config
  end

  def format_all
    return format_text if @config.output_format == :text
    
    format_json
  end

  private

  def format_text
    output = []
    
    @matches.group_by(&:file_path).each do |file, file_matches|
      output << "\n#{'=' * 60}"
      output << "File: #{file}"
      output << '-' * 40
      
      file_matches.sort_by { |m| [m[:line_number], m[:start]] }.each_with_index do |match, idx|
        line = match[:text]
        
        # Truncate long lines for readability
        if line.length > 120
          truncated = line[0...58].strip + '...' + line[-58..-1].strip
          output << "  [#{idx+1}] #{truncated}"
        else
          output << "  [#{idx+1}] #{line}"
        end
        
        # Show context if requested or for very long lines
        if @config.output_format == :text || line.length > 80
          output << "    Pattern: #{@config.compiled[match[:pattern_index]].source}"
          output << "    Position: #{match[:start]}-#{match[:end]}"
          output << "    Line #: #{match[:line_number]}"
        end
      end
      
      output << '-' * 40
    end
    
    output.join("\n")
  end

  def format_json
    grouped = @matches.group_by(&:file_path).map do |file, matches|
      {
        file: file,
        count: matches.size,
        matches: matches.map.with_index(1) do |m, i|
          {
            id: i,
            pattern: @config.compiled[m[:pattern_index]].source,
            text: m[:text],
            line_number: m[:line_number],
            position: "#{m[:start]}-#{m[:end]}",
            snippet: truncate(m[:text])
          }
        end
      }
    end
    
    grouped.to_json(indent: 2)
  end

  def truncate(text, max_length = 100)
    if text.length > max_length
      mid = (max_length - 3) / 2
      "#{text[0...mid]}..." + text[-(max_length - mid)..-1]
    else
      text
    end
  end
end

class MatchStrings
  def initialize(patterns: [], recursive: false, case_sensitive: false, output_format: :text)
    @config = Config.new(
      patterns: patterns,
      recursive: recursive,
      case_sensitive: case_sensitive,
      output_format: output_format
    )
  end

  def run(directory, output_file: nil)
    scanner = FileScanner.new(@config)
    scanner.scan!(directory)
    
    formatter = OutputFormatter.new(matches: @matches, config: @config)
    result = formatter.format_all
    
    if output_file
      File.write(output_file, result)
      puts "Results written to #{output_file}"
    else
      puts result
    end
    
    result
  end

  def matches
    @matches ||= []
  end

  private

  attr_reader :config
end

# ============== Demo / Entry Point ==============

if __FILE__ == $0
  # Default patterns for demo
  DEFAULT_PATTERNS = [
    'password|passwd|pwd',
    '/\*.*?\*/',       # Comments
    '\b(http://|https://)', # URLs
    '\b(email|user@|admin)', # Common keywords
  ].freeze

  def run_demo
    puts "=" * 60
    puts "YARA-Style String Matcher (Ruby)"
    puts "=" * 60
    
    patterns = DEFAULT_PATTERNS.dup
    directory = ARGV[0] || '.'
    
    puts "\nScanning: #{directory}"
    puts "Patterns: #{patterns.inspect}"
    puts "-" * 40

    matcher = MatchStrings.new(patterns: patterns, recursive: true)
    output = matcher.run(directory)
    
    stats = {
      files_scanned: matcher.instance_variable_get(:@scanner)&.files&.size || 0,
      total_matches: output.scan(/\[(\d+)\]/).flatten.sum rescue 0
    }

    puts "\n" + "=" * 60
    puts "Summary:"
    puts "  Files scanned: #{stats[:files_scanned]}"
    puts "  Total matches: #{stats[:total_matches]} (approximate)"
    puts "=" * 60
  end

  run_demo
end