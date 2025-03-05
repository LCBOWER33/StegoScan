# StegoScan

## Overview

StegoScan.py is a Python script designed for automated website and local steganography detection and basic malware scanning. It supports common file types like png, jpg, bin, pdf, docx, wav, and mp3. It utilizes advanced AI models such as YOLO and TrOCR for object and text detection of potentially embeded images/messages. The script is optimized for Linux and will install necessary dependencies automatically.

## Features

* Web Scraping & File Downloading: Extracts and downloads specific file types from URLs.

* Image Processing & Steganography Analysis:

* Extracts images from PDFs and DOCX files.

* Detects steganographic messages in images using stegano, stegdetect, and zsteg.

* Object Detection & Text Recognition for embeded images:

* Uses YOLOv8 for object detection.

* Uses TrOCR for handwriting recognition.

* Basic Malware & ELF File Analysis:

* Audio & Binary File Analysis:

* Uses binwalk for binary file structure extraction.

* Multi-threading Support: Improves performance for large-scale file processing.

# Test

1. LSB Steganography

<p align="center">
  <img src="images/demo.gif" width="700" height="400" >
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

