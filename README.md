# PEar: PE Analysis in Ruby

PEar intends to 
 - Surface “interesting” qualities of the file in one command what would otherwise involve multiple tools.
 - Provide a basic level of intelligence around indicators atypical of non-malware.
 - Provide hints towards next analysis activities.

## Usage

    bundle
    ruby pear.rb <filename> <OPTIONS>

### Options:

 - `-v` Verbose: output all logging (default is only warnings and script progress information).
 - `-vt` Virus Total: open file's VirusTotal page after completion the run.

## Major Components

 - [PEdump](https://github.com/zed-0xff/pedump)

## Resources

 - [This list of PE section names](http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/)
 - [Imphash algorithm](https://secana.github.io/PeNet/articles/imphash.html)

## Acknowledgements

 - [Evan Gaustad](https://github.com/egaustad)