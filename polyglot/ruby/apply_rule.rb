require 'find'
require 'pathname'
require 'fileutils'

# ============== Data Classes ==============

class Match
  attr_reader :file_path, :rule_name, :string_name, :offset, :text
  
  def initialize(file_path:, rule_name:, string_name:, offset:, text:)
    @file_path = file_path
    @rule_name = rule_name
    @string_name = string_name
    @offset = offset
    @text = text
  end
  
  def to_s
    "#{@file_path}:#{@rule_name} - #{@string_name} (#{format_offset(@offset)})"
  end
  
  private
  
  def format_offset(offset)
    if offset.is_a?(Integer) && offset > 0
      "byte #{offset}"
    else
      "N/A"
    end
  end
end

class Rule
  attr_reader :name, :strings, :conditions
  
  def initialize(name:, strings: [], conditions: [])
    @name = name
    @strings = strings
    @conditions = conditions
  end
  
  def to_s
    "#{@name} - #{@strings.size} strings"
  end
end

# ============== Parser ==============

class YaraParser
  def self.parse(text)
    rules = []
    
    text.scan(/rule\s+(\w+)\s*\{[^}]+\}/m) do |match|
      name = match[1]
      rule_block = match.last(1)
      
      strings = extract_strings(rule_block)
      conditions = extract_conditions(rule_block)
      
      rules << Rule.new(name: name, strings: strings, conditions: conditions)
    end
    
    rules
  end
  
  private
  
  def self.extract_strings(rule_block)
    strings = []
    
    rule_block.scan(/\$([a-zA-Z0-9_]+)\s*=\s*(?:"([^"]+)"|\/(.+)\/)/) do |match|
      name, literal, regex = match[1], match[2], match[3]
      
      if literal
        pattern = escape_regex(literal)
        strings << { name: name, type: :literal, pattern: pattern }
      elsif regex
        strings << { name: name, type: :regex, pattern: regex }
      end
    end
    
    strings
  end
  
  def self.escape_regex(str)
    str.gsub(/[\\^$.|?*+()[]{}]/) do |m|
      "\\" + m
    end
  end
  
  def self.extract_conditions(rule_block)
    if rule_block =~ /any\s+of\s+them/
      return :any_of_them
    elsif rule_block =~ /all\s+of\s+them/
      return :all_of_them
    else
      return :unknown
    end
  end
end

# ============== Scanner ==============

class YaraScanner
  def self.scan(directory:, rules: [], options: {})
    directory = Pathname.new(directory)
    
    min_file_size = options[:min_file_size] || 0
    max_file_size = options[:max_file_size] || Float::INFINITY
    follow_symlinks = options[:follow_symlinks] || false
    
    matches = []
    
    Find.find(directory, &lambda do |path|
      next if path.directory? && !follow_symlinks
      next if File.symlink?(path) unless follow_symlinks
      
      file_path = Pathname.new(path)
      
      begin
        size = file_path.file_size
        return false if size < min_file_size || size > max_file_size
      rescue Errno::ENOENT, Errno::EACCES
        next
      end
      
      begin
        content = File.read(path)
        matches += scan_content(content, file_path.to_s, rules)
      rescue Errno::EACCES, Errno::ENAMETOOLONG
        next
      end
      
      true
    end)
    
    matches
  end
  
  def self.scan_content(content, file_path, rules)
    all_matches = []
    
    rules.each do |rule|
      rule_matches = scan_rule(rule, content, file_path)
      all_matches.concat(rule_matches) if rule_matches.any?
    end
    
    all_matches
  end
  
  def self.scan_rule(rule, content, file_path)
    matches = []
    
    case rule.conditions
    when :any_of_them, :all_of_them, :unknown
      rule.strings.each do |str|
        next if str.type == :literal
        
        pattern = str.pattern
        offset = find_pattern(content, pattern)
        
        while offset >= 0
          matches << Match.new(
            file_path: file_path,
            rule_name: rule.name,
            string_name: str.name,
            offset: offset,
            text: content[offset..offset + 63]
          )
          
          if pattern.match?(content[0])
            offset = content.index(pattern, offset + 1) || -1
          else
            break
          end
        end
      end
      
    when :literal_strings
      rule.strings.each