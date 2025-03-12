# StegoScan

## Overview

StegoScan.py is a Python script designed for automated website and local steganography detection with basic malware scanning. It supports common file types like png, jpg, bin, pdf, docx, wav, and mp3. It utilizes advanced AI models such as YOLO and TrOCR for object and text detection of potentially embeded images/messages. The script is optimized for Linux and will install necessary dependencies automatically. Whether StegoScan is given an IP address, IP range, webaddress, and or local directory it will ensure its targeting a webserver or directory and scrape then disect appropriate files to feed them into a steganography test suite designed to uncover hidden public communication. 

Steganography being the practice of hiding messages within other non-suspicious data—has seen a notable increase in utilization within criminal activities. Advancements in digital technologies have enabled malicious actors to embed illicit information within seemingly innocuous files such as images, audio, or video. For example, there have been reports suggesting that terrorist organizations have used steganography to conceal instructions within digital photographs posted on the internet. Additionally, the rise of Voice over Internet Protocol (VoIP) communications has led to the development of techniques that hide data within voice streams, making detection even more challenging. 

In the realm of public media, steganography has also made its presence felt. Beyond its malicious uses, it has been employed for legitimate purposes such as digital watermarking, where copyright information is covertly embedded into media files to protect intellectual property rights. This technique allows content creators to trace the distribution of their work and combat unauthorized usage. Furthermore, the concept of social steganography has emerged, where individuals hide messages within cultural references, idioms, or pop culture content shared publicly, making the underlying messages visible only to certain audiences.

Given the increasing use of steganography in cybercrime, terrorism, and covert communications, it is crucial to develop tools that can scan websites for these hidden messages. Criminals and malicious actors exploit digital steganography to secretly exchange data, such as stolen credentials, malware commands, or illicit instructions, all while avoiding detection by traditional cybersecurity measures. Without the ability to scan and analyze web content for embedded messages, law enforcement and security agencies may struggle to track illegal activities, leading to potential threats to national security, financial systems, and personal privacy. Additionally, with the rise of misinformation and covert influence campaigns, steganographic techniques could be leveraged to spread hidden propaganda or coordinate disinformation efforts. Implementing scanning mechanisms would help identify and mitigate these risks while balancing privacy concerns, ensuring that steganography is not misused for nefarious purposes.

## Features

* Web scraping and file downloading to extract and download specific file types from URLs, IP addresses and ranges.

* Local directory extraction and testing.

* Image processing and steganography analysis.

* Extracts images from PDFs and DOCX files.

* Detects steganographic messages in images using stegano, stegdetect, and zsteg.

* Object Detection & Text Recognition for embeded images:

* Uses YOLOv8 for object detection.

* Uses TrOCR for handwriting and digital writing recognition.

* Basic Malware & ELF File Analysis.

* Audio & Binary File Analysis.

* Uses binwalk for binary file structure extraction.

* Multi-threading Support: Improves performance for large-scale file processing.

# Test

1. LSB Steganography

<p align="center">
  <img src="images/detection_results.gif" width="700" height="400" >
</p>

2. ...

# Installation

## Clone the repository
git clone <repository-url>
cd <repository-folder>

## Run the script; it will automatically create a virtual environment and install dependencies
python cl_test.py

# Usage

The script can be run with different arguments to perform various tasks.

## Basic Usage

python cl_test.py -u "https://example.com" -t "pdf,jpg,png" -n 10 -o "downloads" -m "all"

# Arguments:

-u, --url : Base URL(s), IP address(es), or IP range(s) to scrape files from.

-t, --types : Comma-separated list of file extensions to download (* for all files).

-n, --num : Number of files to download.

-o, --output : Output directory.

-m, --mode : Test mode to specify specific tests (e.g., lsb,hist) or all for all tests.

-l, --local : Path to a local file or directory for analysis.

# Example Commands

## Download files from a URL
python cl_test.py -u "https://example.com" -t "jpg,png" -n 5 -o "downloads"

## Analyze a local directory
python cl_test.py -l "path/to/local/files" -t "*" -o "downloads" -m "all"

# Dependencies

The script automatically installs required dependencies, including:

requests

beautifulsoup4

pdf2image

python-docx

stegano

pillow

opencv-python

numpy

matplotlib

tqdm

torch

transformers

ultralytics

PyPDF2

yara-python

# Notes

Linux users: The script installs poppler-utils, stegdetect, binwalk, and zsteg automatically.

GPU acceleration is used if a CUDA-compatible GPU is detected.

# Future Enhancements

Expand malware analysis with more YARA rules.

Improve object detection using advanced image processing techniques.

Automate Google Drive scanning and crawling functionalities.

# License

This project is open-source and available under the MIT License.

