require 'pedump'
require 'action_view'
require 'colors'

class Pear
	include ActionView::Helpers::TextHelper
	attr_reader :path, :dump, :warnings
	def initialize(**params)
		@path = params[:path]
		@dump = PEdump.dump @path
		@warnings = []
	end

	def static_analysis
		unless dump.pe?
			puts 'Not a PE file'.hl(:red)
			return
		end
		analyze_headers
		analyze_imports
		analyze_resources
		analyze_strings
	rescue => e
		puts 'Error:'.hl(:red)
		puts e.hl(:red)
		return
	end

	def analyze_headers
		puts ('Analyzing File Header').hl(:blue)
		ap @dump.pe.image_file_header
		puts ('Analyzing File Optional Header').hl(:blue)
		ap @dump.pe.image_optional_header
		puts ('Analyzing Sections').hl(:blue)
		@dump.pe.section_table.each{ |section| puts section.Name }
	end

	def analyze_imports
		puts ('Analyzing ' + pluralize(dump.imports.size, 'Import')).hl(:blue)
		dump.imports.each do |import|
			puts import.module_name
		end
	end

	def analyze_resources
		puts ('Analyzing ' + pluralize(dump.resources.size, 'Resource')).hl(:blue)
		dump.resources.each do |resource|
			puts resource
		end
	end

	def analyze_strings
		puts ('Analyzing ' + pluralize(dump.strings.size, 'String')).hl(:blue)
		dump.strings.each do |string|
			puts string
		end
	end
end

puts 'Running PE Analyzer in Ruby v0.1'.hl(:blue)
pear = Pear.new(path: ARGV[0])
unless pear.path
	puts 'Path not provided.'.hl(:red)
else
	pear.static_analysis()
	puts 'Warnings:'.hl(:blue)
	if pear.warnings.empty?
		puts 'No warnings to report!'.hl(:green)
	else
		pear.warnings.each { |warning| puts warning.hl(:red) }
	end
end
puts 'Terminating PEar'.hl(:blue)