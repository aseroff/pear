# PEar: PE Analysis in Ruby

PEar intends to perform static malware analysis on PE (.exe, et al) files. 

## Usage

    bundle
    ruby pear.rb <filename>

## Static Analysis Checklist

 - Compares timestamps
 - Checks strings for URIs
 - Checks and returns imphash
 - ~~Checks section names~~
 - ~~Checks section sizes~~

## Components

 - [PEdump](https://github.com/zed-0xff/pedump)
 - [This list of PE section names](http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/)

## Acknowledgements

 - [Evan Gaustad](https://github.com/egaustad)