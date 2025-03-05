# StegoScan

Overview

cl_test.py is a Python script designed for automated file downloading, image processing, steganography detection, malware scanning, and object recognition. It supports multiple file types and utilizes advanced AI models such as YOLO and TrOCR for object and text detection. The script is optimized for both Windows and Linux and can install necessary dependencies automatically.

Features

Automated Virtual Environment Setup: Creates and manages a Python virtual environment.

Dependency Management: Installs missing Python packages automatically.

Cross-Platform Support: Works on Windows and Linux, including Windows Subsystem for Linux (WSL).

Web Scraping & File Downloading: Extracts and downloads specific file types from URLs.

Image Processing & Steganography Analysis:

Extracts images from PDFs and DOCX files.

Detects steganographic messages in images using stegano, stegdetect, and zsteg.

Object Detection & Text Recognition:

Uses YOLOv8 for object detection.

Uses TrOCR for handwriting recognition.

Malware & ELF File Analysis:

Scans ELF binaries using YARA rules.

Checks file entropy to detect obfuscation or encryption.

Audio & Binary File Analysis:

Converts MP3 to WAV for deeper analysis.

Uses binwalk for binary file structure extraction.

Multi-threading Support: Improves performance for large-scale file processing.

Installation

# Clone the repository
git clone <repository-url>
cd <repository-folder>

# Run the script; it will automatically create a virtual environment and install dependencies
python cl_test.py

Usage

The script can be run with different arguments to perform various tasks.

Basic Usage

python cl_test.py -u "https://example.com" -t "pdf,jpg,png" -n 10 -o "downloads" -m "all"

Arguments:

-u, --url : Base URL(s), IP address(es), or IP range(s) to scrape files from.

-t, --types : Comma-separated list of file extensions to download (* for all files).

-n, --num : Number of files to download.

-o, --output : Output directory.

-m, --mode : Test mode to specify specific tests (e.g., lsb,hist) or all for all tests.

-l, --local : Path to a local file or directory for analysis.

Example Commands

# Download files from a URL
python cl_test.py -u "https://example.com" -t "jpg,png" -n 5 -o "downloads"

# Analyze a local directory
python cl_test.py -l "path/to/local/files" -t "*" -o "downloads" -m "all"

Dependencies

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

Notes

Windows users: Ensure poppler is installed and added to PATH for PDF processing.

Linux users: The script installs poppler-utils, stegdetect, binwalk, and zsteg automatically.

GPU acceleration is used if a CUDA-compatible GPU is detected.

Future Enhancements

Expand malware analysis with more YARA rules.

Improve object detection using advanced image processing techniques.

Automate Google Drive scanning and crawling functionalities.

License

This project is open-source and available under the MIT License.

