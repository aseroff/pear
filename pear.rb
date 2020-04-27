# frozen_string_literal: true

require 'os'
require 'pedump'
require 'digest/md5'
require 'date'
require 'action_view'
require 'colors'

class Pear
  attr_reader :path, :dump, :hash, :warnings
  include ActionView::Helpers::TextHelper

  URL_REGEX = %r{\A(?:(?:https?|ftp)://)(?:\S+(?::\S*)?@)?(?:(?!10(?:\.\d{1,3}){3})(?!127(?:\.\d{1,3}){3})(?!169\.254(?:\.\d{1,3}){2})(?!192\.168(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?\z}i.freeze

  SCARY_RESOURCE_TYPES = %w[EXE DLL].freeze

  # source: http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
  POPULAR_SECTION_NAMES = {
    '.00cfg': 'Control Flow Guard (CFG) section (added by newer versions of Visual Studio)',
    '.apiset': 'a section present inside the apisetschema.dll',
    '.arch': 'Alpha-architecture section',
    '.autoload_text': 'cygwin/gcc; the Cygwin DLL uses a section to avoid copying certain data on fork.',
    '.bindat': 'Binary data (also used by one of the downware installers based on LUA)',
    '.bootdat': 'section that can be found inside Visual Studio files; contains palette entries',
    '.bss': 'Uninitialized Data Section',
    '.BSS': 'Uninitialized Data Section',
    '.buildid': 'gcc/cygwin; Contains debug information (if overlaps with debug directory)',
    '.CLR_UEF': '.CLR Unhandled Exception Handler section; see https: //github.com/dotnet/coreclr/blob/master/src/vm/excep.h',
    '.code': 'Code Section',
    '.cormeta': '.CLR Metadata Section',
    '.complua': 'Binary data, most likely compiled LUA (also used by one of the downware installers based on LUA)',
    '.CRT': 'Initialized Data Section  (C RunTime)',
    '.cygwin_dll_common': 'cygwin section containing flags representing Cygwin’s capabilities; refer to cygwin.sc and wincap.cc inside Cygwin run-time',
    '.data': 'Data Section',
    '.DATA': 'Data Section',
    '.data1': 'Data Section',
    '.data2': 'Data Section',
    '.data3': 'Data Section',
    '.debug': 'Debug info Section',
    '.debug$F': 'Debug info Section (Visual C++ version <7.0)',
    '.debug$P': 'Debug info Section (Visual C++ debug information: precompiled information)',
    '.debug$S': 'Debug info Section (Visual C++ debug information: symbolic information)',
    '.debug$T': 'Debug info Section (Visual C++ debug information: type information)',
    '.drectve': 'directive section (temporary, linker removes it after processing it; should not appear in a final PE image)',
    '.didat': 'Delay Import Section',
    '.didata': 'Delay Import Section',
    '.edata': 'Export Data Section',
    '.eh_fram': 'gcc/cygwin; Exception Handler Frame section',
    '.export': 'Alternative Export Data Section',
    '.fasm': 'FASM flat Section',
    '.flat': 'FASM flat Section',
    '.gfids': 'section added by new Visual Studio (14.0); purpose unknown',
    '.giats': 'section added by new Visual Studio (14.0); purpose unknown',
    '.gljmp': 'section added by new Visual Studio (14.0); purpose unknown',
    '.glue_7t': 'ARMv7 core glue functions (thumb mode)',
    '.glue_7': 'ARMv7 core glue functions (32-bit ARM mode)',
    '.idata': 'Initialized Data Section  (Borland)',
    '.idlsym': 'IDL Attributes (registered SEH)',
    '.impdata': 'Alternative Import data section',
    '.import': 'Alternative Import data section',
    '.itext': 'Code Section  (Borland)',
    '.ndata': 'Nullsoft Installer section',
    '.orpc': 'Code section inside rpcrt4.dll',
    '.pdata': 'Exception Handling Functions Section (PDATA records)',
    '.rdata': 'Read-only initialized Data Section  (MS and Borland)',
    '.reloc': 'Relocations Section',
    '.rodata': 'Read-only Data Section',
    '.rsrc': 'Resource section',
    '.sbss': 'GP-relative Uninitialized Data Section',
    '.script': 'Section containing script',
    '.shared': 'Shared section',
    '.sdata': 'GP-relative Initialized Data Section',
    '.srdata': 'GP-relative Read-only Data Section',
    '.stab': 'Created by Haskell compiler (GHC)',
    '.stabstr': 'Created by Haskell compiler (GHC)',
    '.sxdata': 'Registered Exception Handlers Section',
    '.text': 'Code Section',
    '.text0': 'Alternative Code Section',
    '.text1': 'Alternative Code Section',
    '.text2': 'Alternative Code Section',
    '.text3': 'Alternative Code Section',
    '.textbss': 'Section used by incremental linking',
    '.tls': 'Thread Local Storage Section',
    '.tls$': 'Thread Local Storage Section',
    '.udata': 'Uninitialized Data Section',
    '.vsdata': 'GP-relative Initialized Data',
    '.xdata': 'Exception Information Section',
    '.wixburn': 'Wix section; see https: //github.com/wixtoolset/wix3/blob/develop/src/burn/stub/StubSection.cpp',
    '.wpp_sf ': 'section that is most likely related to WPP (Windows software trace PreProcessor); not sure how it is used though; the code inside the section is just a bunch of routines that call FastWppTraceMessage that in turn calls EtwTraceMessage',
    'BSS': 'Uninitialized Data Section  (Borland)',
    'CODE': 'Code Section (Borland)',
    'DATA': 'Data Section (Borland)',
    'DGROUP': 'Legacy data group section',
    'edata': 'Export Data Section',
    'idata': 'Initialized Data Section  (C RunTime)',
    'INIT': 'INIT section (drivers)',
    'minATL': 'Section that can be found inside some ARM PE files; purpose unknown; .exe files on Windows 10 also include this section as well; its purpose is unknown, but it contains references to ___pobjectentryfirst,___pobjectentrymid,___pobjectentrylast pointers used by Microsoft: : WRL: : Details: : ModuleBase: : … methods described e.g. here, and also referenced by .pdb symbols; so, looks like it is being used internally by Windows Runtime C++ Template Library (WRL) which is a successor of Active Template Library (ATL); further research needed',
    'text': 'Alternative Code Section'
  }.freeze

  COMMON_PACKER_SECTION_NAMES = {
    '.aspack': 'Aspack packer',
    '.adata': 'Aspack packer/Armadillo packer',
    'ASPack': 'Aspack packer',
    '.ASPack': 'ASPAck Protector',
    '.boom': 'The Boomerang List Builder (config+exe xored with a single byte key 0x77)',
    '.ccg': 'CCG Packer (Chinese Packer)',
    '.charmve': 'Added by the PIN tool',
    'BitArts': 'Crunch 2.0 Packer',
    'DAStub': 'DAStub Dragon Armor protector',
    '!EPack': 'Epack packer',
    '.ecode': 'Built with EPL',
    '.edata': 'Built with EPL',
    '.enigma1': 'Enigma Protector',
    '.enigma2': 'Enigma Protector',
    'FSG!': 'FSG packer (not a section name, but a good identifier)',
    '.gentee': 'Gentee installer',
    'kkrunchy': 'kkrunchy Packer',
    'lz32.dll': 'Crinkler',
    '.mackt': 'ImpRec-created section',
    '.MaskPE': 'MaskPE Packer',
    'MEW': 'MEW packer',
    '.mnbvcx1': 'most likely associated with Firseria PUP downloaders',
    '.mnbvcx2': 'most likely associated with Firseria PUP downloaders',
    '.MPRESS1': 'Mpress Packer',
    '.MPRESS2': 'Mpress Packer',
    '.neolite': 'Neolite Packer',
    '.neolit': 'Neolite Packer',
    '.nsp1': 'NsPack packer',
    '.nsp0': 'NsPack packer',
    '.nsp2': 'NsPack packer',
    'nsp1': 'NsPack packer',
    'nsp0': 'NsPack packer',
    'nsp2': 'NsPack packer',
    '.packed': 'RLPack Packer (first section)',
    'pebundle': 'PEBundle Packer',
    'PEBundle': 'PEBundle Packer',
    'PEC2TO': 'PECompact packer',
    'PECompact2': 'PECompact packer (not a section name, but a good identifier)',
    'PEC2': 'PECompact packer',
    'pec': 'PECompact packer',
    'pec1': 'PECompact packer',
    'pec2': 'PECompact packer',
    'pec3': 'PECompact packer',
    'pec4': 'PECompact packer',
    'pec5': 'PECompact packer',
    'pec6': 'PECompact packer',
    'PEC2MO': 'PECompact packer',
    'PELOCKnt': 'PELock Protector',
    '.perplex': 'Perplex PE-Protector',
    'PESHiELD': 'PEShield Packer',
    '.petite': 'Petite Packer',
    '.pinclie': 'Added by the PIN tool',
    'ProCrypt': 'ProCrypt Packer',
    '.RLPack': 'RLPack Packer (second section)',
    '.rmnet': 'Ramnit virus marker',
    'RCryptor': 'RPCrypt Packer',
    '.RPCrypt': 'RPCrypt Packer',
    '.seau': 'SeauSFX Packer',
    '.sforce3': 'StarForce Protection',
    '.shrink1': 'Shrinker',
    '.shrink2': 'Shrinker',
    '.shrink3': 'Shrinker',
    '.spack': 'Simple Pack (by bagie)',
    '.svkp': 'SVKP packer',
    'Themida': 'Themida Packer',
    '.Themida': 'Themida Packer',
    '.taz': 'Some version os PESpin',
    '.tsuarch': 'TSULoader',
    '.tsustub': 'TSULoader',
    'PEPACK!!': 'Pepack',
    '.Upack': 'Upack packer',
    '.ByDwing': 'Upack Packer',
    'UPX0': 'UPX packer',
    'UPX1': 'UPX packer',
    'UPX2': 'UPX packer',
    'UPX3': 'UPX packer',
    'UPX!': 'UPX packer',
    '.UPX0': 'UPX Packer',
    '.UPX1': 'UPX Packer',
    '.UPX2': 'UPX Packer',
    '.vmp0': 'VMProtect packer',
    '.vmp1': 'VMProtect packer',
    '.vmp2': 'VMProtect packer',
    'VProtect': 'Vprotect Packer',
    '.winapi': 'Added by API Override tool',
    'WinLicen': 'WinLicense (Themida) Protector',
    '_winzip_': 'WinZip Self-Extractor',
    '.WWPACK': 'WWPACK Packer',
    '.WWP32': 'WWPACK Packer (WWPack32)',
    '.yP': 'Y0da Protector',
    '.y0da': 'Y0da Protector'
  }.freeze

  def initialize(**params)
    @path = params[:path]
    @dump = PEdump.dump @path
    @hash = Digest::MD5.hexdigest(File.open(@path).read)
    @warnings = []
  end

  def log(message, level = :default)
    colors = { warn: :red, suspicious: :yellow, success: :green, info: :blue }
    message = (level == :default ? message : message.hl(colors[level].to_sym))
    warnings << message if level.in? %i[warn suspicious]
    puts message
  end

  def static_analysis
    log "Starting analysis of #{path}", :info
    unless dump.pe?
      puts 'Not a PE file'.hl(:red)
      return
    end
    analyze_headers
    analyze_sections
    analyze_imports
    analyze_resources
    analyze_strings
    true
  rescue StandardError => e
    puts 'Error:'.hl(:red)
    puts e&.hl(:red)
    nil
  end

  def analyze_headers
    log 'Analyzing File Header', :info
    log 'Timestamp: ' + DateTime.strptime(dump.pe.image_file_header.TimeDateStamp.to_s, '%s').strftime('%x %T')
    log 'Analyzing File Optional Header', :info
    log "Image size: #{dump.pe.image_optional_header.SizeOfImage}"
    debug = dump.pe.image_optional_header.DataDirectory.find { |d| d['type'] == 'DEBUG' }
    log "Debug directory present at offset #{debug.va}" if debug&.va&.positive?
  end

  def analyze_sections
    log "Analyzing #{pluralize(dump.pe.section_table.size, 'Sections')}", :info
    dump.pe.section_table.each do |section|
      section_name = section.Name
      if section_name.in? Pear::POPULAR_SECTION_NAMES.keys.map(&:to_s)
        log "Unsuspicious section name: #{section_name} (#{Pear::POPULAR_SECTION_NAMES[section_name.to_sym]})"
      elsif section_name.in? Pear::COMMON_PACKER_SECTION_NAMES.keys.map(&:to_s)
        log "Known packer section name: #{section_name} (#{Pear::COMMON_PACKER_SECTION_NAMES[section_name.to_sym]})", :suspicious
      else
        log "Unrecognized section name: #{section_name}", :warn
      end
      vsize = section.VirtualSize
      rsize = section.SizeOfRawData
      if rsize < vsize * 0.2
        log "Vast discrepancy between virtual size (#{vsize}) and raw size (#{rsize}) of section #{section_name} (possible unpacking)!", :warn
      else
        log "Virtual size (#{vsize}) and raw size (#{rsize}) of section seem normal."
      end
    end
  end

  def analyze_imports
    log "Analyzing #{pluralize(dump.imports.size, 'Imported Module')}", :info
    imports = dump.imports
    formatted_imports = []
    imphash_failure = false
    imports.each do |import|
      import.first_thunk.each do |function|
        imphash_name = import.module_name.split('.').first + '.' + (function.name || function.ordinal.to_s)
        if function.name && !imphash_failure
          log imphash_name
          formatted_imports << imphash_name.downcase
        else
          unless imphash_failure
            puts 'This script cannot resolve the name of ordinally linked functions. Imphash cannot be calculated.'.hl(:yellow)
            imphash_failure = true
          end
          log imphash_name
        end
      end
    end
    log "Imphash: #{Digest::MD5.hexdigest formatted_imports.join(',')}" unless imphash_failure
  end

  def analyze_resources
    log "Analyzing #{pluralize(dump.resources.size, 'Resource')}", :info
    dump.resources.each do |resource|
      msg = "#{resource.name} (#{resource.type}): #{resource.size} bytes"
      if resource.type.in? PEdump::ROOT_RES_NAMES
        log msg
      elsif resource.type.in? SCARY_RESOURCE_TYPES
        log msg + ' - dangerous resource type.', :warn
      else
        log msg + ' - unrecognized resource type.', :suspicious
      end
    end
  end

  def analyze_strings
    log "Analyzing #{pluralize(dump.strings.size, 'String')}", :info
    dump.strings.each do |string|
      url = URL_REGEX.match string.value
      if url
        log "URL found in strings: #{string.value}", :warn
      else
        log string.value
      end
    end
  end
end

puts 'Running PE Analyzer in Ruby (PEar) v0.1'.hl(:blue)
pear = Pear.new(path: ARGV[0])
if pear.path
  if pear.static_analysis
    pear.log 'Static analysis completed successfully.', :success
  else
    pear.log 'Static analysis failed to complete successfully.', :warn
  end
  if pear.warnings.empty?
    pear.log '0 Warnings', :success
  else
    puts pluralize(pear.warnings.size, 'Warning').+':'.hl(:yellow)
    pear.warnings.each { |warning| puts warning }
    unless ARGV[1] == '-nvt'
      system OS.open_file_command, 'https://www.virustotal.com/gui/file/' + pear.hash
    end
  end
else
  puts 'Path to PE file required.'.hl(:red)
end
puts 'Terminating PEar successfully!'.hl(:green)
