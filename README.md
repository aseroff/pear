# PEar: PE Analysis in Ruby

PEar intends to perform static malware analysis on PE (.exe, et al) files. 

## Usage

    bundle
    ruby pear.rb <filename> <OPTIONS>

### Options:

 - `-nvt` No Virus Total: won't open a VT page for the file after completing the run.

## Static Analysis Checklist

 - Compares timestamps
 - Checks for scary imports
 - Does something more with resources
 - ~~Checks strings for URIs~~
 - ~~Returns imphash~~
 - ~~Checks section names~~
 - ~~Checks section sizes~~

## Components

 - [PEdump](https://github.com/zed-0xff/pedump)
 - [This list of PE section names](http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/)

## Acknowledgements

 - [Evan Gaustad](https://github.com/egaustad)