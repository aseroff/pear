# frozen_string_literal: true

require 'pedump'
require 'digest'
require 'action_view'
require 'colors'

include ActionView::Helpers::TextHelper

class Pear
  attr_reader :path, :dump, :warnings

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

  COMMON_SECTION_NAMES = {
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
    @warnings = []
  end

  def static_analysis
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
    puts e.hl(:red)
    nil
  end

  def analyze_headers
    puts 'Analyzing File Header'.hl(:blue)
    # ap dump.pe.image_file_header
    puts 'Analyzing File Optional Header'.hl(:blue)
    # ap dump.pe.image_optional_header
  end

  def analyze_sections
    puts "Analyzing #{pluralize(dump.pe.section_table.size, 'Sections')}".hl(:blue)
    dump.pe.section_table.each do |section|
      section_name = section.Name
      if section_name.in? Pear::POPULAR_SECTION_NAMES.keys.map(&:to_s)
        section_name_notice = "Unsuspicious section name: #{section_name}".hl(:green)
      elsif section_name.in? Pear::COMMON_SECTION_NAMES.keys.map(&:to_s)
        section_name_notice = "Known packer section name: #{section_name} (#{Pear::COMMON_SECTION_NAMES[section_name.to_sym]})".hl(:yellow)
        warnings << section_name_notice
      else
        section_name_notice = "Unrecognized section name: #{section_name}".hl(:red)
        warnings << section_name_notice
      end
      puts section_name_notice
      vsize = section.VirtualSize
      rsize = section.SizeOfRawData
      if rsize < vsize * 0.2
        section_size_notice = "Vast discrepancy between virtual size (#{vsize}) and raw size (#{rsize}) of section #{section_name} (possible unpacking)!".hl(:red)
        warnings << section_size_notice
      else
        section_size_notice = "Virtual size (#{vsize}) and raw size (#{rsize}) of section seem normal.".hl(:green)
      end
      puts section_size_notice
    end
  end

  def analyze_imports
    puts "Analyzing #{pluralize(dump.imports.size, 'Import')}".hl(:blue)
    dump.imports.each do |import|
      puts import.module_name
      # puts Digest::MD5.hexdigest import.module_name
    end
  end

  def analyze_resources
    puts "Analyzing #{pluralize(dump.resources.size, 'Resource')}".hl(:blue)
    dump.resources.each do |resource|
      puts resource
    end
  end

  def analyze_strings
    puts "Analyzing #{pluralize(dump.strings.size, 'String')}".hl(:blue)
    dump.strings.each do |string|
      puts string
    end
  end
end

puts 'Running PE Analyzer in Ruby v0.1'.hl(:blue)
pear = Pear.new(path: ARGV[0])
if pear.path
	puts "Starting analysis of #{pear.path}".hl(:blue)
  if pear.static_analysis
    puts 'Static analysis completed successfully.'.hl(:green)
  else
    puts 'Static analysis failed to complete successfully.'.hl(:red)
  end
  if pear.warnings.empty?
    puts '0 Warnings'.hl(:green)
  else
    puts (pluralize(pear.warnings.size, 'Warning').+':').hl(:yellow)
    pear.warnings.each { |warning| puts warning }
  end
else
  puts 'Path to PE file required.'.hl(:red)
end
puts 'Terminating PEar successfully!'.hl(:green)
