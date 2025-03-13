# StegoScan

## Overview

StegoScan.py is a Python script designed for automated website and local steganography detection with basic malware scanning. It supports common file types like png, jpg, bin, pdf, docx, wav, and mp3. It utilizes advanced AI models such as YOLO and TrOCR for object and text detection of potentially embeded images/messages. The script is optimized for Linux and will install necessary dependencies automatically. Whether StegoScan is given an IP address, IP range, webaddress, and or local directory it will ensure its targeting a webserver or directory and scrape then disect appropriate files to feed them into a steganography test suite designed to uncover hidden public communication. 

Steganography being the practice of hiding messages within other non-suspicious data—has seen a notable increase in utilization within criminal activities. Advancements in digital technologies have enabled malicious actors to embed illicit information within seemingly innocuous files such as images, audio, or video. For example, there have been reports suggesting that terrorist organizations have used steganography to conceal instructions within digital photographs posted on the internet. Additionally, the rise of Voice over Internet Protocol (VoIP) communications has led to the development of techniques that hide data within voice streams, making detection even more challenging. 

In the realm of public media, steganography has also made its presence felt. Beyond its malicious uses, it has been employed for legitimate purposes such as digital watermarking, where copyright information is covertly embedded into media files to protect intellectual property rights. This technique allows content creators to trace the distribution of their work and combat unauthorized usage. Furthermore, the concept of social steganography has emerged, where individuals hide messages within cultural references, idioms, or pop culture content shared publicly, making the underlying messages visible only to certain audiences.

Given the increasing use of steganography in cybercrime, terrorism, and covert communications, it is crucial to develop tools that can scan websites for these hidden messages. Criminals and malicious actors exploit digital steganography to secretly exchange data, such as stolen credentials, malware commands, or illicit instructions, all while avoiding detection by traditional cybersecurity measures. Without the ability to scan and analyze web content for embedded messages, law enforcement and security agencies may struggle to track illegal activities, leading to potential threats to national security, financial systems, and personal privacy. Additionally, with the rise of misinformation and covert influence campaigns, steganographic techniques could be leveraged to spread hidden propaganda or coordinate disinformation efforts. Implementing scanning mechanisms would help identify and mitigate these risks while balancing privacy concerns, ensuring that steganography is not misused for nefarious purposes.

## How StegoScan Works

... 

## Novel Features

...

## General Features

* Web scraping and file downloading to extract and download specific file types from URLs, IP addresses and ranges.

* Local directory extraction and testing.

* Image processing and steganography analysis.

* Extracts images from PDFs and DOCX files.

* Detects steganographic messages in images using stegano, stegdetect, and zsteg.

* Object Detection & Text Recognition for embeded images.

* Uses YOLOv8 for object detection.

* Uses TrOCR for handwriting and digital writing recognition.

* Basic Malware & ELF File Analysis.

* Audio & Binary File Analysis.

* Uses binwalk for binary file structure extraction.

* Multi-threading Support: Improves performance for large-scale file processing.

# Test

1. LSB - Uses stegano Python import to check PNG files for plain text messages hidden in the LSB of the file.

2. Image integrity - Uses Pillow Python import to check PNG and JPG file's integrity.

3. Hist - Uses Matplotlib Python import to generate histograms showing the distribution of RGB color values for PNG and JPG files.

4. Object detection - Uses YOLOv8 and TrORC to test each layer of PNG and JPG files by removing the LSB iterativly and testing only red, green, and blue filters on the image.

<p align="center">
  <img src="images/detection_results.gif" width="700" height="400" >
</p>

5. Jpeg - Uses Stegdetect Linux commandline tool to test JPG files to detect hidden data embedded within images using techniques like jSteg, jphide, Outguess, F5 (header analysis), invisible secrets, appendX and camouflage.

6. Png - Uses Zsteg Linux commandline tool to test PNG to detect LSB steganography, check different color channels (R, G, B, A) and their bit planes, detects common encoding techniques used to hide data in images, payload extraction, text and ASCII hidden messages, and entropy analysis.

7. Audio integrity - Uses Wave Python import to check MP3 and WAV file's integrity.

8. Audio dectection - Uses Librosa Python import to generate audio spectrogram's for MP3 and WAV files that are then ran through YOLOv8 and TrORC to check for images or messages hidden in the depiction of the frequency values for the file over the time length of the file.

9. Binary - Uses Binwalk Linux commandline tool to test binary files for embedded files & data, identifies known file signatures inside a binary (e.g., ZIP, PNG, ELF, etc.), detects firmware components within a binary image, compressed and encrypted data, finds compressed data (e.g., LZMA, GZIP, BZIP2) inside files, flags encrypted or obfuscated data, file system signatures, recognizes embedded file systems (e.g., SquashFS, JFFS2, EXT, FAT), detects compiled executables (ELF, PE, Mach-O), identifies bootloaders and firmware components, and entropy analysis

10. Elf check - Uses YARA rules, magic bytes, Linux file command, and entropy analysis to check all files for embeded malware.

## Basic Usage

sudo python StegoScan.py -u "https://example.com" -t "*" -o "downloads" -m "all"

# Arguments:

-u, --url : Base URL(s), IP address(es), or IP range(s) to scrape files from.

-t, --types : Comma-separated list of file extensions to download (* for all files).

-n, --num : Number of files to download.

-o, --output : Output directory.

-m, --mode : Test mode to specify specific tests (e.g., lsb,hist) or "all" for all tests.

-l, --local : Path to a local file or directory for analysis.

# Example Commands

## Download files from a URL
sudo python StegoScan.py -u "https://example.com" -t "jpg,png" -n 5 -o "downloads" -m "all"

## Analyze a local directory
sudo python StegoScan.py -l "path/to/local/files" -t "*" -o "downloads" -m "lsb,hist,png"

# Notes

All scraped files will be stored in the output directory supplied in the execution.

Automatically creates and installs new enviroment for all nessasary Python imports.

The script installs poppler-utils, stegdetect, binwalk, and zsteg automatically.

GPU acceleration is used if a CUDA-compatible GPU is detected.

# Future Enhancements - Anticipated completion date: May 2025

Create GUI implentation if no commandline arguments are supplied. 

Expand test suite to include Strings, Exiftool, StegSeek, WavSteg, OpenPuff, and Stegcracker.

Expand to a web crawler and allow for diffrent search depths. 

Expand malware analysis with more YARA rules.

Improve object detection using advanced image processing techniques.

Expand to Google Drive scanning.

# License

This project is open-source and available under the MIT License.

