# PEar: PE Analysis in Ruby

PEar intends to perform static malware analysis on PE (.exe, et al) files. 

## Usage

    bundle
    ruby pear.rb <filename> <OPTIONS>

### Options:

 - `-nvt` No Virus Total: won't open a VT page for the file after completing the run.

## Components

 - [PEdump](https://github.com/zed-0xff/pedump)
 - [This list of PE section names](http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/)

## Acknowledgements

 - [Evan Gaustad](https://github.com/egaustad)