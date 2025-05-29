import math
import os
import sys
import subprocess
import platform
import venv
import threading

VENV_DIR = "myenv"  # Name of the virtual environment folder

# Thread-safe print with color
print_lock = threading.Lock()

def prRed(skk):
    with print_lock:
        print("\033[91m{}\033[00m".format(skk))


def prGreen(skk): 
    with print_lock:
        print("\033[92m{}\033[00m".format(skk))


def prYellow(skk):
    with print_lock:
        print("\033[93m{}\033[00m".format(skk))


def prLightPurple(skk):
    with print_lock:
        print("\033[94m{}\033[00m".format(skk))


def prPurple(skk):
    with print_lock:
        print("\033[95m{}\033[00m".format(skk))


def prCyan(skk):
    with print_lock:
        print("\033[96m{}\033[00m".format(skk))


def prLightGray(skk):
    with print_lock:
        print("\033[97m{}\033[00m".format(skk))


def prBlack(skk):
    with print_lock:
        print("\033[98m{}\033[00m".format(skk))


# Required third-party packages with corresponding pip names
required_packages = {
    "requests": "requests",
    "bs4": "beautifulsoup4",
    "pdf2image": "pdf2image",
    "docx": "python-docx",
    "stegano": "stegano",
    "PIL": "pillow",
    "cv2": "opencv-python",
    "numpy": "numpy",
    "matplotlib.pyplot": "matplotlib",
    "pydub": "pydub",
    "tqdm": "tqdm",
    "torch": "torch",
    "transformers": "transformers",
    "ultralytics": "ultralytics",
    "PyPDF2": "PyPDF2",
    "yara": "yara-python",  # YARA for malware analysis
    "librosa": "librosa",
    "fitz": "pymupdf",
    "ctypes": "ctypes",
    "hashlib": "hashlib",
    "io": "io",
    "ttkbootstrap": "ttkbootstrap",
    "tempfile": "tempfile",
}


def create_virtual_env():
    """Creates a virtual environment if it doesn't exist."""
    if not os.path.exists(VENV_DIR):
        print(f"Creating virtual environment: {VENV_DIR}")
        venv.create(VENV_DIR, with_pip=True)


def get_venv_python():
    """Returns the path to the Python interpreter inside the virtual environment."""
    if os.name == "nt":  # For Windows, path might be different
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    else:
        return os.path.join(VENV_DIR, "bin", "python3")


def install_missing_packages():
    """Ensure all required Python packages are installed in the virtual environment."""
    python_exec = get_venv_python()
    for module, package in required_packages.items():
        try:
            subprocess.run([python_exec, "-c", f"import {module}"], check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print(f"Installing missing package: {package}...")
            subprocess.check_call([python_exec, "-m", "pip", "install", package])


def install_linux_dependencies():
    """Ensure Linux-specific dependencies (like Poppler for pdf2image) are installed."""

    if platform.system() == "Linux":
        try:
            subprocess.run(["dpkg", "-s", "poppler-utils"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            prGreen("poppler-utils is already installed.")
        except subprocess.CalledProcessError as e:
            print("poppler-utils is not installed or not detected. Attempting to install...")
            try:
                subprocess.check_call(["sudo", "apt-get", "update"])
                subprocess.check_call(["sudo", "apt-get", "install", "-y", "poppler-utils"])
                prGreen("poppler-utils has been successfully installed.")
            except subprocess.CalledProcessError as install_error:
                prRed(f"Failed to install poppler-utils. Error: {install_error}")


def run_script_in_venv():
    """Restarts the script inside the virtual environment if not already inside it."""
    python_exec = get_venv_python()

    # Avoid infinite loops by checking if we're already inside the venv
    if sys.prefix == os.path.abspath(VENV_DIR):  # Already inside the venv
        prGreen("Script is already running inside the virtual environment.")
        return  # Do nothing, exit the function

    print(f"Running script inside virtual environment: {VENV_DIR}")

    # Ensure that the python executable exists
    if not os.path.isfile(python_exec):
        prRed(f"Error: Python executable not found at {python_exec}")
        sys.exit(1)

    # Build the command to restart the script inside the virtual environment
    command = [python_exec] + sys.argv

    # Explicitly set the working directory to where the script is
    script_dir = os.path.dirname(os.path.abspath(__file__))

    try:
        print(f"Restarting the script with command: {command}")
        subprocess.check_call(command, cwd=script_dir, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        prRed(f"Error during restart: {e}")
        sys.exit(1)

    sys.exit()  # Ensure the script exits after launching the new one


# Setup environment and dependencies
create_virtual_env()
run_script_in_venv()  # Relaunch in venv if needed
install_linux_dependencies()
# configure_windows_poppler()
install_missing_packages()

import warnings
import logging
import sys
import ctypes
import transformers

# Suppress warnings
warnings.simplefilter("ignore", category=DeprecationWarning)
warnings.simplefilter("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=UserWarning, module='torch')

# Suppress logging from models
transformers.logging.set_verbosity_error()
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("torch").setLevel(logging.ERROR)
logging.getLogger("ultralytics").setLevel(logging.ERROR)

# Optional: Redirect stderr to suppress all warnings (use with caution)
sys.stderr = open(os.devnull, "w")

import argparse
import requests
import shutil
import ipaddress
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urljoin, unquote, urlparse
import re

from pdf2image import convert_from_path
from PyPDF2 import PdfReader
from docx import Document

from stegano import lsb
import imghdr
from PIL import Image
import cv2
import numpy as np
import matplotlib.pyplot as plt
from pydub import AudioSegment
import wave

from tqdm import tqdm

import torch
from transformers import TrOCRProcessor, VisionEncoderDecoderModel
from ultralytics import YOLO
from datetime import datetime
from collections import Counter
import yara
import librosa
import librosa.display

import fitz
import hashlib
import io

# add these to import list
import argparse
import tkinter as tk
from tkinter import ttk, filedialog, Toplevel, Label, Button
import ttkbootstrap as tb
import webbrowser
from PIL import Image, ImageTk
import requests
import io
import tempfile


cv2.setNumThreads(max(1, os.cpu_count() - 1))

print(f"[INFO] OpenCV will use {cv2.getNumThreads()} threads")

# Check if CUDA (GPU) is available, otherwise fallback to CPU
device = "cuda" if torch.cuda.is_available() else "cpu"

# Load the pre-trained YOLOv8 model
model = YOLO("yolov8l.pt").to(device)  # Use 'yolov8s.pt' for a smaller, faster model
model.overrides['verbose'] = False  # Suppress model output

# Load the pre-trained TrOCR model and processor
processor_handwritten = TrOCRProcessor.from_pretrained("microsoft/trocr-base-handwritten")
model_handwritten = VisionEncoderDecoderModel.from_pretrained("microsoft/trocr-base-handwritten")

processor_printed = TrOCRProcessor.from_pretrained("microsoft/trocr-base-printed")
model_printed = VisionEncoderDecoderModel.from_pretrained("microsoft/trocr-base-printed")

# Ensure the model is on GPU if available
# model_trocr = model_trocr.to(device)

# Define YARA rules to detect ELF files and potential malware traits
YARA_RULES = """
rule ELF_Detection {
    meta:
        description = "Detects ELF files based on magic bytes"
    strings:
        $magic = { 7F 45 4C 46 }  // ELF Magic Bytes
    condition:
        $magic at 0
}

rule ELF_Malware {
    meta:
        description = "Detects suspicious ELF executables (packed, obfuscated, or malicious traits)"
    strings:
        $upx = "UPX!" nocase  // UPX-packed files
        $syscall = { B8 00 00 00 00 FF E0 }  // Suspicious syscall execution
    condition:
        any of ($upx, $syscall)
}
"""

results_folder = ""

# GitHub README URL
README_URL = "https://github.com/LCBOWER33/StegoScan/blob/main/README.md"

max_threads = max(1, multiprocessing.cpu_count() - 1)
semaphore = threading.Semaphore(max_threads)


def open_directory(path):
    """Opens the specified directory in the system's file explorer."""
    if os.path.exists(path):
        if os.name == 'nt':  # Windows
            subprocess.Popen(f'explorer "{path}"')
        elif os.name == 'posix':  # macOS / Linux
            subprocess.Popen(['open', path])  # For macOS
            # subprocess.Popen(['xdg-open', path])  # For Linux
    else:
        prRed(f"Directory not found: {path}")
# Example usage:
directory_path = "/home/kali/Desktop/riley_output/results_20250501_175944"  # Replace with the actual path
# open_directory(directory_path)


def run_silent_command(command):
    """Run a shell command silently, capturing output but not displaying it."""
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def check_and_install_poppler():
    if platform.system() != "Linux":
        prRed("This script is intended for Linux systems only.")
        return

    if shutil.which("pdftoppm"):
        prGreen("Poppler is already installed.")
        return

    print("Poppler is not installed. Installing now...")

    try:
        distro = subprocess.check_output(["lsb_release", "-is"], text=True).strip().lower()
    except FileNotFoundError:
        distro = ""

    try:
        if "ubuntu" in distro or "debian" in distro:
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "install", "-y", "poppler-utils"], check=True)
        elif "fedora" in distro:
            subprocess.run(["sudo", "dnf", "install", "-y", "poppler-utils"], check=True)
        else:
            prRed("Unsupported Linux distribution. Please install poppler-utils manually.")
            return

        prGreen("Poppler installed successfully.")
    except subprocess.CalledProcessError as e:
        prRed(f"Error installing Poppler: {e}")


def get_wikipedia_image(url):
    """Extract direct image URL from a Wikipedia file information page."""
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        image_tag = soup.find('div', class_='fullImageLink')
        if image_tag:
            image_link = image_tag.find('a')
            if image_link and 'href' in image_link.attrs:
                return urljoin(url, image_link['href'])
    except requests.RequestException as e:
        prRed(f"Failed to get direct Wikipedia image URL from {url}: {e}")
    return None


def is_valid_url(url):
    """Check if a URL is valid."""
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)


def download_file(url, output_dir):
    try:
        if 'wikipedia.org' in url and '/wiki/File:' in url:
            direct_url = get_wikipedia_image(url)
            if direct_url:
                url = direct_url
            else:
                prRed(f"Skipping Wikipedia file page: {url}")
                return

        if not is_valid_url(url):
            prRed(f"Invalid URL skipped: {url}")
            return

        response = requests.get(url, stream=True, timeout=5)
        response.raise_for_status()

        parsed_url = urlparse(url)
        file_name = os.path.basename(unquote(parsed_url.path))
        if not file_name or '.' not in file_name:
            file_name = "unknown_file"

        file_extension = file_name.split('.')[-1].lower() if '.' in file_name else 'unknown'

        file_type_dir = os.path.join(output_dir, file_extension)
        os.makedirs(file_type_dir, exist_ok=True)
        output_path = os.path.join(file_type_dir, file_name)

        with open(output_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        prGreen(f"Downloaded: {url} -> {output_path}")
    except requests.RequestException as e:
        prRed(f"Failed to download {url}: {e}")


def get_file_links(url, file_types, limit, all_files):
    valid_extensions = {"png", "jpg", "jpeg", "pdf", "docx", "mp3", "wav", "bin"}
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()

        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            full_url = urljoin(url, href)

            if not is_valid_url(full_url):
                continue  # Skip invalid URLs

            parsed_href = urlparse(full_url).path
            file_ext = parsed_href.split('.')[-1].lower()

            if all_files:
                if file_ext in valid_extensions or ('wikipedia.org' in full_url and '/wiki/File:' in full_url):
                    links.add(full_url)
            elif file_ext in file_types:
                links.add(full_url)
                if len(links) >= limit:
                    break

        return list(links)[:limit] if not all_files else list(links)
    except requests.RequestException as e:
        prRed(f"Failed to fetch links from {url}: {e}")
        return []


def copy_local_files(source, destination):
    if os.path.isdir(source):
        for file_name in os.listdir(source):
            full_source_path = os.path.join(source, file_name)
            if os.path.isfile(full_source_path):
                file_extension = file_name.split('.')[-1] if '.' in file_name else 'unknown'
                file_type_dir = os.path.join(destination, file_extension)
                os.makedirs(file_type_dir, exist_ok=True)
                full_destination_path = os.path.join(file_type_dir, file_name)
                shutil.copy(full_source_path, full_destination_path)
                # print(f"Copied: {full_source_path} -> {full_destination_path}")
    elif os.path.isfile(source):
        file_name = os.path.basename(source)
        file_extension = file_name.split('.')[-1] if '.' in file_name else 'unknown'
        file_type_dir = os.path.join(destination, file_extension)
        os.makedirs(file_type_dir, exist_ok=True)
        full_destination_path = os.path.join(file_type_dir, file_name)
        shutil.copy(source, full_destination_path)
        # print(f"Copied: {source} -> {full_destination_path}")
    else:
        prRed(f"Invalid local path: {source}")


def is_web_server(ip):
    try:
        response = requests.get(f"http://{ip}/", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False


def process_ip_range(ip_range):
    return [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False)]


def download_from_source(source, file_types, limit, all_files, output_dir, visited_urls=set(), max_depth=1, depth=0):
    if depth > max_depth or source in visited_urls:
        return
        
    print("IN DOWNLOAD FROM SOURCE")

    visited_urls.add(source)
    prGreen(f"Crawling: {source} (Depth {depth})")

    file_links = get_file_links(source, file_types, limit, all_files)
    for file_url in file_links:
        download_file(file_url, output_dir)

    # Extract and follow links recursively
    try:
        response = requests.get(source, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(source, href)
            if is_valid_url(full_url) and full_url not in visited_urls:
                download_from_source(full_url, file_types, limit, all_files, output_dir, visited_urls, max_depth,
                                     depth + 1)
    except requests.RequestException as e:
        prRed(f"Failed to crawl {source}: {e}")
        

def threaded_download(source, *args):
    with semaphore:
        download_from_source(source, *args)


def calculate_image_entropy(image):
    """Calculate the entropy of an image to detect complexity."""
    grayscale_image = image.convert('L')
    histogram = grayscale_image.histogram()
    hist_probabilities = [float(h) / sum(histogram) for h in histogram]
    return -sum(p * np.log2(p) for p in hist_probabilities if p > 0)


def is_duplicate(image_bytes, hashes):
    """Check if an image is a duplicate using MD5 hashing."""
    hash_md5 = hashlib.md5(image_bytes).hexdigest()
    if hash_md5 in hashes:
        return True
    hashes.add(hash_md5)
    return False


def extract_images_from_pdf(pdf_path, output_folder, min_width=50, min_height=50, entropy_threshold=3.0):
    """
    Extract only distinct, complex raster images from a PDF.

    :param pdf_path: Path to the input PDF file
    :param output_folder: Folder to save extracted images
    :param min_width: Minimum width to filter small elements
    :param min_height: Minimum height to filter small elements
    :param entropy_threshold: Minimum entropy to keep complex images
    """
    os.makedirs(output_folder, exist_ok=True)

    try:
        doc = fitz.open(pdf_path)
    except Exception as e:
        prRed(f"Error opening PDF: {e}")
        return

    image_count = 0
    hashes = set()

    for page_number in range(len(doc)):
        page = doc[page_number]
        images = page.get_images(full=True)

        if not images:
            continue

        for img_index, img in enumerate(images):
            try:
                xref = img[0]
                base_image = doc.extract_image(xref)

                if not base_image or "image" not in base_image:
                    continue

                image_bytes = base_image["image"]
                image_ext = base_image.get("ext", "png").lower()
                width = base_image.get("width", 0)
                height = base_image.get("height", 0)

                # Filter for valid raster images
                if image_ext not in ("jpeg", "jpg", "png") or width < min_width or height < min_height:
                    continue

                # Detect duplicate images
                if is_duplicate(image_bytes, hashes):
                    continue

                # Calculate entropy to filter out simple images
                image = Image.open(io.BytesIO(image_bytes))
                entropy = calculate_image_entropy(image)
                if entropy < entropy_threshold or image.mode in ['1', 'L']:
                    continue

                # Save the image
                image_filename = f"image_{page_number + 1}_{img_index + 1}.{image_ext}"
                image_path = os.path.join(output_folder, image_filename)
                with open(image_path, "wb") as image_file:
                    image_file.write(image_bytes)

                image_count += 1
                prGreen(f"Extracted: {image_path} (Entropy: {entropy:.2f}, {width}x{height})")
            except Exception as e:
                prRed(f"Error extracting image on page {page_number + 1}: {e}")

    prGreen(f"Total images extracted: {image_count}")


def extract_images_from_docx(docx_path, output_dir):
    doc = Document(docx_path)
    count = 0
    for i, rel in enumerate(doc.part.rels):
        if "image" in doc.part.rels[rel].target_ref:
            image = doc.part.rels[rel].target_part.blob
            image_path = os.path.join(output_dir, f'image_{count + 1}.png')
            with open(image_path, "wb") as f:
                f.write(image)
            count += 1
    # print(f"Extracted {count} images from {docx_path}")


def extract_from_file(output_dir):
    pdf_dir = os.path.join(output_dir, "pdf")
    os.makedirs(pdf_dir, exist_ok=True)

    docx_dir = os.path.join(output_dir, "docx")
    os.makedirs(docx_dir, exist_ok=True)

    png_dir = os.path.join(output_dir, "png")
    os.makedirs(png_dir, exist_ok=True)

    for filename in os.listdir(pdf_dir):
        f = os.path.join(pdf_dir, filename)
        # checking if it is a file
        # print("IN PDF")
        if os.path.isfile(f):
            prGreen(f)
            extract_images_from_pdf(f, output_dir)

    # print("OUT")

    """for filename in os.listdir(docx_dir):
        f = os.path.join(docx_dir, filename)
        # checking if it is a file
        print("IN DOCX")
        if os.path.isfile(f):
            # print(f)
            extract_images_from_docx(f, png_dir)"""

def clean_up_folder(target_dir):
    if not os.path.isdir(target_dir):
        prRed(f"'{target_dir}' is not a valid directory.")
        return

    for filename in os.listdir(target_dir):
        file_path = os.path.join(target_dir, filename)

        if os.path.isfile(file_path):
            ext = os.path.splitext(filename)[1].lower().lstrip(".")

            # Group jpeg and jpg into same folder
            if ext in ("jpeg", "jpg"):
                ext_folder = "jpg"
            else:
                ext_folder = ext or "unknown"

            # Create destination folder if it doesn't exist
            dest_folder = os.path.join(target_dir, ext_folder)
            os.makedirs(dest_folder, exist_ok=True)

            # Move the file
            shutil.move(file_path, os.path.join(dest_folder, filename))



def convert_image_to_bin(image_path, out_file):
    # Open image
    with Image.open(image_path) as img:
        with open(out_file, 'wb') as bin_file:
            # Convert image to bytes and write to .bin file
            img_bytes = img.tobytes()
            bin_file.write(img_bytes)


def process_images(output_dir):
    # Define the folders for jpg and png images
    folders = ['jpg', 'png']

    # Create the bin_files directory if it doesn't exist
    bin_dir = os.path.join(output_dir, "bin")
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    png_dir = os.path.join(output_dir, "png")
    if os.path.isdir(png_dir):
        for filename in os.listdir(png_dir):
            f = os.path.join(png_dir, filename)
            # checking if it is a file
            if os.path.isfile(f):
                # print(bin_dir)
                filename_with_extension = os.path.basename(filename)
                filename_without_extension = os.path.splitext(filename_with_extension)[0]
                out_file = str(bin_dir + "/" + filename_without_extension + ".bin")
                convert_image_to_bin(f, out_file)
                # print(f"Converted {filename} to {out_file}")

    jpg_dir = os.path.join(output_dir, "jpg")
    if os.path.isdir(jpg_dir):
        for filename in os.listdir(jpg_dir):
            f = os.path.join(jpg_dir, filename)
            # checking if it is a file
            if os.path.isfile(f):
                # print(bin_dir)
                filename_with_extension = os.path.basename(filename)
                filename_without_extension = os.path.splitext(filename_with_extension)[0]
                out_file = str(bin_dir + "/" + filename_without_extension + ".bin")
                convert_image_to_bin(f, out_file)
                # print(f"Converted {filename} to {out_file}")


def is_meaningful_text(text):
    """Check if extracted text is meaningful (not gibberish)."""
    if not text or len(text) < 2:  # Ignore empty or single-character text
        return False
    # Allow only words with letters, numbers, or common symbols
    return bool(re.search(r"[a-zA-Z0-9]", text))


def extract_text(image, processor, model):
    """Run OCR and return meaningful extracted text."""
    pixel_values = processor(image, return_tensors="pt").pixel_values
    generated_ids = model.generate(pixel_values)
    extracted_text = processor.batch_decode(generated_ids, skip_special_tokens=True)[0]
    return extracted_text if is_meaningful_text(extracted_text) else None


def detect_objects(image):
    """Runs YOLO model on the image and returns True if an object is detected."""
    results = model(image)
    for result in results:
        if len(result.boxes) > 0:
            return True  # At least one object detected
    return False


def enhance_image_for_ocr(image):
    """Prepares the image to improve OCR accuracy."""
    # Convert to grayscale
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Apply adaptive histogram equalization to enhance contrast
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)

    # Resize to a standard size (helps OCR model generalize better)
    resized = cv2.resize(enhanced, (512, 512))

    return resized


def detect_text(image):
    """Runs OCR (TrOCR) and ensures only meaningful text is considered."""
    # Preprocess image for better OCR accuracy
    preprocessed_img = enhance_image_for_ocr(image)

    # Convert to PIL Image for TrOCR processing
    pil_image = Image.fromarray(preprocessed_img).convert("RGB")

    # Get pixel values for model input
    pixel_values = processor_handwritten(images=pil_image, return_tensors="pt").pixel_values.to(device)

    # Perform OCR prediction
    generated_ids = model_handwritten.generate(pixel_values)
    transcription = processor_handwritten.decode(generated_ids[0], skip_special_tokens=True).strip()

    # Apply filtering: Ignore results if text length is too short or contains mostly non-alphanumeric characters
    if len(transcription) < 3 or sum(c.isalnum() for c in transcription) / len(transcription) < 0.5:
        return False, ""  # Ignore if it's too short or mostly symbols

    return True, transcription


# I think the above line is making it to where there is going to save all the file variations

def process_and_save(image, variant_name):
    """
    Runs YOLO and TrOCR on the image.
    Saves the image if objects or text are detected.
    """
    object_detected = detect_objects(image)

    # Check for text in both grayscale and color versions using TrOCR
    text_detected_grayscale, text_grayscale = detect_text(image)  # , is_grayscale=True)
    text_detected_color, text_color = detect_text(image)  # , is_grayscale=False)

    text_detected = text_detected_grayscale or text_detected_color

    if object_detected:  # or text_detected:
        # NEED TO MAKE IT ROUTE TO THE OUTPUT DIR THEN HERE
        object_detection_dir = os.path.join(results_folder, "object_detection")
        os.makedirs(object_detection_dir, exist_ok=True)

        save_path = os.path.join(results_folder, f"object_detection/{variant_name}.png")
        # print("\n\n" + save_path + "\n\n")
        cv2.imwrite(save_path, image)
        # print(f"Saved: {save_path} (Object: {object_detected}, Text: {text_detected})")

        # If text was detected, print it
        # if text_detected_grayscale:
        #    print(f"Text (grayscale): {text_grayscale}")
        # if text_detected_color:
        #    print(f"Text (color): {text_color}")

    # Show the processed image
    object_detection_dir = os.path.join(results_folder, "object_detection")
    os.makedirs(object_detection_dir, exist_ok=True)

    save_path = os.path.join(results_folder, f"object_detection/{variant_name}.png")
    cv2.imwrite(save_path, image)

    # cv2.imshow(f"Processed: {variant_name}", image)
    # cv2.waitKey(500)  # Show for 500ms before moving to the next image
    # cv2.destroyAllWindows()


def extract_lsb_and_normalize(image, bits):
    """
    Extracts the specified number of least significant bits and normalizes them.
    - Keeps only the lowest `bits` LSBs of each channel.
    - Normalizes the result to fill the 8-bit range for visibility.
    """
    lsb_image = image & ((1 << bits) - 1)  # Keep only the `bits` least significant bits
    return (lsb_image * (255 // ((1 << bits) - 1))).astype(np.uint8)  # Normalize


def is_elf_using_yara(filepath):
    """Check if a file is an ELF executable using YARA rules."""
    rule = yara.compile(source=YARA_RULES)
    matches = rule.match(filepath)
    return any(match.rule == "ELF_Detection" for match in matches)


def is_suspicious_elf(filepath):
    """Check if an ELF file has potential malware traits using YARA rules."""
    rule = yara.compile(source=YARA_RULES)
    matches = rule.match(filepath)
    return any(match.rule == "ELF_Malware" for match in matches)


def is_elf_using_magic(filepath):
    """Check if a file starts with ELF magic bytes."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
        return magic == b'\x7FELF'
    except Exception as e:
        prRed(f"Error reading file: {e}")
        return False


def check_with_file_command(filepath):
    """Check the file type using the 'file' command (Linux/Mac only)."""
    try:
        result = subprocess.run(["file", "-b", filepath], capture_output=True, text=True)
        return "ELF" in result.stdout
    except Exception as e:
        prRed(f"Error running file command: {e}")
        return False


def calculate_entropy(filepath):
    """Calculate Shannon entropy to detect packed or encrypted ELF files."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        counter = Counter(data)
        total = len(data)
        entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
        return entropy
    except Exception as e:
        prRed(f"Error calculating entropy: {e}")
        return 0


# TODO Add in the following test
def run_exiftool(image_path):
    """Run exiftool and capture output."""
    result = run_silent_command(f"exiftool '{image_path}'")
    if result:
        prGreen("ExifTool Output:\n", result)
    else:
        prRed("ExifTool: No metadata found or failed.")


def run_stegseek(image_path):
    """Run stegseek and capture output."""
    result = run_silent_command(f"stegseek '{image_path}'")
    if result:
        prGreen("StegSeek Output:\n", result)
    else:
        prRed("StegSeek: No hidden data found or failed.")


def run_stegexpose(image_path):
    """Run stegexpose and capture output."""
    result = run_silent_command(f"stegexpose '{image_path}'")
    if result:
        prGreen("StegExpose Output:\n", result)
    else:
        prRed("StegExpose: No hidden data found or failed.")


def run_stegorat(file_path):
    """Run stego-rat and capture output."""
    result = run_silent_command(f"stegorat '{file_path}'")
    if result:
        prGreen("StegoRAT Output:\n", result)
    else:
        prRed("StegoRAT: No data found or failed.")


def run_stegosuite(image_path):
    """Run stegosuite and capture output."""
    result = run_silent_command(f"stegosuite '{image_path}'")
    if result:
        prGreen("StegoSuite Output:\n", result)
    else:
        prRed("StegoSuite: No data found or failed.")


def extract_and_crack_wavsteg(input_wav, output_dir):
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Name for the extracted file
    extracted_file = os.path.join(output_dir, "extracted_data.bin")

    # Step 1: Extract the hidden data from the WavSteg file using WavSteg
    try:
        print(f"Extracting data from {input_wav}...")
        extract_command = f"wavsteg -x {input_wav} -o {extracted_file}"
        subprocess.run(extract_command, shell=True, check=True)
        prGreen(f"Data extraction complete: {extracted_file}")
    except subprocess.CalledProcessError as e:
        prRed(f"Error extracting data: {e}")
        return

    # Step 2: Create the hash file for John the Ripper (using the extracted data)
    try:
        print("Creating hash file for John the Ripper...")
        hash_file = os.path.join(output_dir, "hash.txt")
        hash_command = f"john --format=raw-md5 {extracted_file} --wordlist=/path/to/rockyou.txt"
        subprocess.run(hash_command, shell=True, check=True)
        prGreen("John the Ripper hash file created.")
    except subprocess.CalledProcessError as e:
        prRed(f"Error creating hash file: {e}")
        return

    # Step 3: Use John the Ripper to attempt cracking
    try:
        print(f"Attempting to crack with rockyou wordlist...")
        crack_command = f"john --restore {hash_file}"
        subprocess.run(crack_command, shell=True, check=True)

        # Step 4: Check if the password was found
        check_command = "john --show " + hash_file
        result = subprocess.run(check_command, shell=True, capture_output=True, text=True)

        if result.stdout:
            prGreen("Password found! Cracking successful.")
            cracked_file = os.path.join(output_dir, "cracked_data.bin")
            # Save the cracked file (assumes the password is in the output of john)
            with open(cracked_file, "wb") as f:
                f.write(result.stdout.encode())
            prGreen(f"Cracked file saved to {cracked_file}")
        else:
            prRed("Password not found. Cracking failed.")

    except subprocess.CalledProcessError as e:
        prRed(f"Error during cracking: {e}")
        return


# --------------------------------------------------------------
# TEST SUITE

# TODO add in the new test and replace one old
def t_lsb(output_dir):
    def process_file(f, filename):
        try:
            hidden_message = lsb.reveal(f)
            lsb_dir = os.path.join(results_folder, "lsb")
            os.makedirs(lsb_dir, exist_ok=True)
            shutil.copy(f, os.path.join(lsb_dir, filename))
            prGreen(f"[LSB] Hidden message detected in {filename}")
        except:
            pass

    png_dir = os.path.join(output_dir, "png")
    if os.path.isdir(png_dir):
        files = [f for f in os.listdir(png_dir) if os.path.isfile(os.path.join(png_dir, f))]
        with ThreadPoolExecutor(max_workers=os.cpu_count() - 1) as executor:
            for filename in tqdm(files, desc="LSB test: "):
                f = os.path.join(png_dir, filename)
                executor.submit(process_file, f, filename)
    prGreen("LSB TEST DONE")


def image_integrity(output_dir):
    def verify_image(f, filename, ext):
        try:
            with Image.open(f) as img:
                img.verify()
        except Exception:
            dest_dir = os.path.join(results_folder, "image_integrity")
            os.makedirs(dest_dir, exist_ok=True)
            shutil.copy(f, os.path.join(dest_dir, filename))
            prGreen(f"[INTEGRITY] Corrupted or suspicious image: {filename}")

    for ext in ["png", "jpg"]:
        dir_path = os.path.join(output_dir, ext)
        if os.path.isdir(dir_path):
            files = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
            with ThreadPoolExecutor(max_workers=os.cpu_count() - 1) as executor:
                for filename in tqdm(files, desc=f"Image integrity {ext.upper()} test: "):
                    f = os.path.join(dir_path, filename)
                    executor.submit(verify_image, f, filename, ext)
    prGreen("IMAGE INTEGRITY TEST DONE")


def object_detection(output_dir):
    # Load the original image
    png_dir = os.path.join(output_dir, "png")
    if os.path.isdir(png_dir):
        for filename in tqdm(os.listdir(png_dir), desc="Object detection PNG test: "):
            f = os.path.join(png_dir, filename)
            # checking if it is a file
            if os.path.isfile(f):
                # print(f)
                image_path = f
                original_image = cv2.imread(image_path)

                # Step 1: Run detection on the original image
                process_and_save(original_image.copy(), f"{filename}_original")

                # Step 2: Isolate RGB channels and run detection on each
                rgb_channels = ['red', 'green', 'blue']
                for i, color in enumerate(rgb_channels):
                    isolated_image = np.zeros_like(original_image)
                    isolated_image[:, :, i] = original_image[:, :, i]  # Keep only one channel active

                    process_and_save(isolated_image, f"{filename}_{color}_only")

                # Step 3: Iterate over LSB removals (1 to 8 bits) and run detection
                for bits in range(1, 9):  # Extract 1-bit to 8-bit LSBs
                    lsb_image = extract_lsb_and_normalize(original_image, bits)
                    process_and_save(lsb_image, f"{filename}_lsb_{bits}_bits_normalized")

                # cv2.destroyAllWindows()

    jpg_dir = os.path.join(output_dir, "jpg")
    if os.path.isdir(jpg_dir):
        for filename in tqdm(os.listdir(jpg_dir), desc="Object detection JPG test: "):
            f = os.path.join(jpg_dir, filename)
            # checking if it is a file
            if os.path.isfile(f):
                # print(f)
                image_path = f
                original_image = cv2.imread(image_path)

                # Step 1: Run detection on the original image
                process_and_save(original_image.copy(), f"{filename}_original")

                # Step 2: Isolate RGB channels and run detection on each
                rgb_channels = ['red', 'green', 'blue']
                for i, color in enumerate(rgb_channels):
                    isolated_image = np.zeros_like(original_image)
                    isolated_image[:, :, i] = original_image[:, :, i]  # Keep only one channel active

                    process_and_save(isolated_image, f"{filename}_{color}_only")

                # Step 3: Iterate over LSB removals (1 to 8 bits) and run detection
                for bits in range(1, 9):  # Extract 1-bit to 8-bit LSBs
                    lsb_image = extract_lsb_and_normalize(original_image, bits)
                    process_and_save(lsb_image, f"{filename}_lsb_{bits}_bits_normalized")

                # cv2.destroyAllWindows()
    print("OBJECT DECTECTION TEST DONE")


def hist(output_dir):
    def process_image(f, filename):
        image = cv2.imread(f, cv2.IMREAD_GRAYSCALE)
        if image is not None:
            plt.hist(image.ravel(), bins=256, range=[0, 256])
            plt.title("Histogram")
            plt.savefig(os.path.join(hist_dir, f"{filename}_histogram.png"))
            plt.close()
            prGreen(f"[HIST] Saved histogram for {filename}")

    hist_dir = os.path.join(results_folder, "hist")
    os.makedirs(hist_dir, exist_ok=True)

    for ext in ["png", "jpg"]:
        dir_path = os.path.join(output_dir, ext)
        if os.path.isdir(dir_path):
            files = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
            with ThreadPoolExecutor(max_workers=os.cpu_count() - 1) as executor:
                for filename in tqdm(files, desc=f"Histogram {ext.upper()} test: "):
                    f = os.path.join(dir_path, filename)
                    executor.submit(process_image, f, filename)
    prGreen("HIST TEST DONE")


def jpeg(output_dir):
    # TODO replace with another tool as stegdetect is out of date
    jpg_dir = os.path.join(output_dir, "jpg")
    if os.path.isdir(jpg_dir):
        for filename in tqdm(os.listdir(jpg_dir), desc="JPEG test: "):
            f = os.path.join(jpg_dir, filename)
            # checking if it is a file
            if os.path.isfile(f):
                # print(f)
                image_path = f
                """Run stegdetect in WSL silently and capture output."""
                # wsl_image_path = image_path.replace("C:\\", "/mnt/c/").replace("\\", "/").lower()
                result = run_silent_command(f"stegdetect -t o {image_path}")

                # Only print results if stegdetect finds something
                if result:
                    jpeg_dir = os.path.join(results_folder, "jpeg")
                    os.makedirs(jpeg_dir, exist_ok=True)

                    shutil.copy(image_path, f"{jpeg_dir}/{filename}")
                    prGreen(f"Stegdetect Output:\n {result}")

    prGreen("JPEG TEST DONE")


def png(output_dir):
    png_dir = os.path.join(output_dir, "png")
    if os.path.isdir(png_dir):
        for filename in tqdm(os.listdir(png_dir), desc="Zsteg test: "):
            # print("IN PNG")
            f = os.path.join(png_dir, filename)
            # checking if it is a file
            if os.path.isfile(f):
                # print(f)
                image_path = f
                """Run zsteg in WSL silently and capture output."""
                # wsl_image_path = image_path.replace("C:\\", "/mnt/c/").replace("\\", "/").lower()
                result = run_silent_command(f"zsteg -a {image_path}")

                if result:
                    png_dir = os.path.join(results_folder, "png")
                    os.makedirs(png_dir, exist_ok=True)

                    shutil.copy(image_path, f"{png_dir}/{filename}")

                    base_name, _ = os.path.splitext(filename)
                    new_filename = f"{base_name}.txt"

                    f = open(f"{png_dir}/{new_filename}", "w")
                    f.write(result)
                    f.close()
                    prGreen(f"Zsteg Output:\n {result}")

    prGreen("PNG TEST DONE")


# TODO make the mp3 to wave a funciton and not duplicated
def audio_integrity(output_dir):
    def check_wav_properties(f, filename):
        try:
            with wave.open(f, "rb") as wav_file:
                integrity_dir = os.path.join(results_folder, "audio_integrity")
                os.makedirs(integrity_dir, exist_ok=True)
                out_file = os.path.join(integrity_dir, f"{os.path.splitext(filename)[0]}.txt")
                with open(out_file, "w") as log:
                    log.write(f"Channels: {wav_file.getnchannels()}\n")
                    log.write(f"Frame rate: {wav_file.getframerate()}\n")
                    log.write(f"Sample width: {wav_file.getsampwidth()}\n")
                    log.write(f"Frames: {wav_file.getnframes()}\n")
                prGreen(f"[AUDIO INTEGRITY] Checked {filename}")
        except Exception as e:
            prRed(f"[AUDIO INTEGRITY] Failed to read {filename}: {e}")

    wav_dir = os.path.join(output_dir, "wav")
    if os.path.isdir(wav_dir):
        files = [f for f in os.listdir(wav_dir) if os.path.isfile(os.path.join(wav_dir, f))]
        with ThreadPoolExecutor(max_workers=os.cpu_count() - 1) as executor:
            for filename in tqdm(files, desc="Audio integrity test: "):
                f = os.path.join(wav_dir, filename)
                executor.submit(check_wav_properties, f, filename)
    prGreen("AUDIO INTEGRITY TEST DONE")


def audio_dectection(output_dir):
    mp3_dir = os.path.join(output_dir, "mp3")
    wav_dir = os.path.join(output_dir, "wav")
    if os.path.isdir(mp3_dir):
        for filename in os.listdir(mp3_dir):
            f = os.path.join(mp3_dir, filename)
            # checking if it is a file
            if os.path.isfile(f):
                # print(f)
                src = f
                file_name = os.path.basename(f)
                file = os.path.splitext(file_name)
                dst = os.path.join(wav_dir, file[0] + ".wav")

                # convert wav to mp3
                sound = AudioSegment.from_mp3(src)
                sound.export(dst, format="wav")

    if os.path.isdir(wav_dir):
        for filename in tqdm(os.listdir(wav_dir), desc="Audio detection test: "):
            f = os.path.join(wav_dir, filename)
            # checking if it is a file
            if os.path.isfile(f):
                # print(f)
                audio_path = f
                # Step 1: Load the audio file and generate spectrogram
                y, sr = librosa.load(audio_path, sr=None)
                D = librosa.amplitude_to_db(np.abs(librosa.stft(y)), ref=np.max)

                # Step 2: Save spectrogram as a high-resolution image (no display)
                base_name, _ = os.path.splitext(filename)
                spectrogram_path = f"{base_name}_spectrogram.png"  # Need to change this
                librosa.display.specshow(D, sr=sr, x_axis="time", y_axis="log")
                plt.axis("off")
                plt.savefig(spectrogram_path)
                plt.close()

                # Step 3: Run YOLOv8 detection (silent execution)
                results = model(spectrogram_path)
                for result in results:
                    if len(result.boxes) > 0:
                        audio_dectection_dir = os.path.join(results_folder, "audio_dectection")
                        os.makedirs(audio_dectection_dir, exist_ok=True)

                        shutil.copy(spectrogram_path,
                                    f"{audio_dectection_dir}/{base_name}_spectrogram.png")  # this needs to be tested further

                # Step 5: Run OCR on spectrogram (both handwritten and printed models)
                image = Image.open(spectrogram_path).convert("RGB")

                # Extract and filter text
                text_handwritten = extract_text(image, processor_handwritten, model_handwritten)
                text_printed = extract_text(image, processor_printed, model_printed)

                # Step 6: Print meaningful results only, Need to save this here
                if text_handwritten:
                    audio_dectection_dir = os.path.join(results_folder, "audio_dectection")
                    os.makedirs(audio_dectection_dir, exist_ok=True)

                    shutil.copy(spectrogram_path, f"{audio_dectection_dir}/{base_name}_spectrogram.png")
                    prGreen("Message found")
                    #prGreen(f"Extracted Handwritten Text: {text_handwritten}")

                if text_printed:
                    audio_dectection_dir = os.path.join(results_folder, "audio_dectection")
                    os.makedirs(audio_dectection_dir, exist_ok=True)

                    shutil.copy(spectrogram_path, f"{audio_dectection_dir}/{base_name}_spectrogram.png")
                    prGreen("Message found")
                    #prGreen(f"Extracted Printed Text: {text_printed}")
    prGreen("AUDIO DECTECTION TEST DONE")


def binary(output_dir):
    bin_dir = os.path.join(output_dir, "bin")
    if os.path.isdir(bin_dir):
        for filename in tqdm(os.listdir(bin_dir), desc="Binary test: "):
            # print("IN BIN")
            f = os.path.join(bin_dir, filename)
            # checking if it is a file
            if os.path.isfile(f):
                # print(f)
                file_path = f
                """Run binwalk in WSL silently and capture output."""
                # wsl_file_path = file_path.replace("C:\\", "/mnt/c/").replace("\\", "/").lower()
                result = run_silent_command(f"binwalk {file_path}")

                if result:
                    binary_dir = os.path.join(results_folder, "binary")
                    os.makedirs(binary_dir, exist_ok=True)

                    shutil.copy(file_path, f"{binary_dir}/{filename}")
                    prYellow(f"Binwalk Output:\n {result}")

    prGreen("BINARY TEST DONE")


def elf_check(output_dir):
    """Main function to check if the file is an ELF executable and detect malware traits."""
    for dirpath, dirnames, filenames in os.walk(output_dir):
        for filename in tqdm(filenames, desc="ELF test: "):
            file_path = os.path.join(dirpath, filename)
            # print(file_path)
            is_elf = (
                    is_elf_using_magic(file_path) or
                    is_elf_using_yara(file_path) or
                    check_with_file_command(file_path)
            )

            if is_elf:
                elf_dir = os.path.join(results_folder, "elf")
                os.makedirs(elf_dir, exist_ok=True)

                shutil.copy(file_path, f"{elf_dir}/{filename}")
                # print(f"[+] {file_path} is an ELF file.")

                # Check for suspicious traits
                if is_suspicious_elf(file_path):
                    prGreen(f"[!] WARNING: {file_path} may contain suspicious traits (packed, obfuscated, or malicious).")

                # Check entropy for potential obfuscation
                entropy = calculate_entropy(file_path)
                # print(f"[*] File entropy: {entropy:.2f}")
                if entropy > 7:
                    pass
                    # print("[!] High entropy detected – possible packing or encryption.")
                elif entropy > 7.5:
                    pass
                    # print("very high")
            else:
                prRed(f"[-] {file_path} is NOT an ELF file.")
    prGreen("ELF TEST DONE")


# --------------------------------------------------------------
def open_readme():
    webbrowser.open(README_URL)


def add_hint(entry, hint_text):
    if entry.get() == "":
        entry.insert(0, hint_text)
        entry.config(foreground="gray")


def remove_hint(entry, hint_text):
    if entry.get() == hint_text:
        entry.delete(0, tk.END)
        entry.config(foreground="white")

        
def handle_input_change(entry, hint_text):
    if entry.get() != hint_text:
        entry.config(foreground="white")
        

def add_context_menu(entry):
    menu = tk.Menu(entry, tearoff=0)

    def cut():
        entry.event_generate("<<Cut>>")

    def copy():
        entry.event_generate("<<Copy>>")

    def paste():
        entry.event_generate("<<Paste>>")

    menu.add_command(label="Cut", command=cut)
    menu.add_command(label="Copy", command=copy)
    menu.add_command(label="Paste", command=paste)

    def show_menu(event):
        try:
            menu.tk_popup(event.x_root + 5, event.y_root + 5)
        finally:
            menu.grab_release()

    entry.bind("<Button-3>", show_menu)
    

def create_gui():
    root = tb.Window(themename="darkly")  # Apply dark theme
    root.title("StegoScan")

    # Load the icon image
    response = requests.get(
        "https://raw.githubusercontent.com/LCBOWER33/StegoScan/main/images/StegoScan_dark_logo.png",
        timeout=5
    )
    response.raise_for_status()

    img_data = response.content
    img = Image.open(io.BytesIO(img_data)).convert("RGBA")
    img = img.resize((32, 32), Image.LANCZOS)

    icon_photo = ImageTk.PhotoImage(img)
    root.icon_photo = icon_photo  # Prevent garbage collection
    root.iconphoto(True, icon_photo)  # Works on macOS/Linux

    # Make the window full screen
    # root.attributes("-fullscreen", True)
    root.configure(bg="#191B1D")
    root.geometry("1050x975")  # Optional, in case you want a fallback size for non-fullscreen
    root.resizable(True, True)

    # Function to toggle full screen on Escape key press
    def toggle_full_screen(event=None):
        """ Toggle between full screen and windowed mode. """
        current_state = root.attributes("-fullscreen")
        root.attributes("-fullscreen", not current_state)

    # Bind Escape key to exit full-screen mode
    root.bind("<Escape>", toggle_full_screen)

    # ASCII Banner (Ensure spacing is preserved)
    # ascii_banner = '''  ___ _                ___
    #  / __| |_ ___ __ _ ___/ __| __ __ _ _ _
    #  \__ \  _/ -_) _` / _ \__ \/ _/ _` | ' \
    #  |___/\__\___\__, \___/___/\__\__,_|_||_|
    #              |___/                       '''

    # Add a label for the ASCII banner
    # banner_label = tk.Label(root, text=ascii_banner, font=("Courier", 10), fg="#00FF00", bg="#040D12", justify="left",
    #                        anchor="w")
    # banner_label.pack(pady=10)  # Adjust spacing

    # Load the image
    response = requests.get("https://raw.githubusercontent.com/LCBOWER33/StegoScan/main/images/StegoScan_dark.png")
    response.raise_for_status()  # Raise error if failed

    image_data = response.content
    image = Image.open(io.BytesIO(image_data))
    banner_image = image.resize((450, 112), Image.LANCZOS)  # Resize to (width, height)
    banner_photo = ImageTk.PhotoImage(banner_image)
    # Display it in a Label
    banner_label = Label(root, image=banner_photo)
    banner_label.pack(pady=10)

    # Use a built-in question icon
    help_icon = tk.PhotoImage(name="::tk::icons::question")  # try to make icon not just help

    # Create a button with the help icon
    button = ttk.Button(root, text="Help", command=open_readme, image=help_icon, compound="center")
    button.pack(pady=20)

    def select_output_dir():
        folder_selected = filedialog.askdirectory()
        output_entry.delete(0, tk.END)
        output_entry.insert(0, folder_selected)
        output_entry.config(foreground="white")  # Ensure text is white

    def select_local_file():
        def choose_file():
            selected_path = filedialog.askopenfilename()
            update_entry(selected_path)
            dialog.destroy()

        def choose_folder():
            selected_path = filedialog.askdirectory()
            update_entry(selected_path)
            dialog.destroy()

        def update_entry(selected_path):
            if selected_path:
                local_entry.delete(0, tk.END)
                local_entry.insert(0, selected_path)
                local_entry.config(foreground="white")  # Ensure text is white

        dialog = Toplevel(root)
        dialog.title("Select Option")
        dialog.configure(bg="#222")
        dialog.geometry("300x150")
        dialog.grab_set()

        Label(dialog, text="Select a file or folder:", foreground="#222", bg="#222", font=("Arial", 12)).pack(pady=10)

        btn_frame = tb.Frame(dialog)
        btn_frame.pack(pady=10)

        tb.Button(btn_frame, text="Select File", command=choose_file, bootstyle="info-outline").pack(side="left",
                                                                                                     padx=10)
        tb.Button(btn_frame, text="Select Folder", command=choose_folder, bootstyle="info-outline").pack(side="left",
                                                                                                         padx=10)

    fields = [
        ("URL(s):", "e.g. https://example.com"),
        ("IP/IP Range(s):", "e.g. 127.0.0.1 or 127.0.0.0/24"),
        ("Number of Downloads:", "e.g 10, if all types it will override this number"),
        ("Max Depth:", "e.g. 2"),
        ("Output Directory:", "Select output folder"),
        ("Local Directory:", "Select a local file or folder"),
    ]

    entries = []
    outer_frame = ttk.Frame(root, width=800, height=350)
    outer_frame.pack(padx=10, pady=10)

    style = ttk.Style()
    style.configure("TFrame", background="#040D12")
    inner_frame = ttk.Frame(outer_frame, style="TFrame", width=150, height=100)
    inner_frame.pack(padx=20, pady=20)
    inner_frame.grid(row=0, column=0, padx=20, pady=20)

    class CheckboxGroup:
        def __init__(self, parent, group_title, options, row, columns):
            self.frame = ttk.LabelFrame(parent, text=group_title, padding=10)
            self.frame.grid(row=row, column=0, columnspan=3, pady=10, sticky="ew")

            self.options = options  # Store option labels
            self.vars = []
            self.select_all_var1 = tk.BooleanVar()
            self.select_all_var2 = tk.BooleanVar()

            label = "Select All"
            if group_title == "File Types":
                chk = ttk.Checkbutton(self.frame, text=label, variable=self.select_all_var2,
                                      command=self.toggle_all_and_disable, bootstyle="primary-round-toggle")


            else:
                chk = ttk.Checkbutton(self.frame, text=label, variable=self.select_all_var1,
                                      command=self.toggle_all, bootstyle="primary-round-toggle")
            chk.grid(row=0, column=0, padx=5, pady=2, sticky="w")

            for i, label in enumerate(options):
                var = tk.BooleanVar()
                self.vars.append(var)
                row, col = divmod(i, columns)

                chk = ttk.Checkbutton(self.frame, text=label, variable=var, bootstyle="primary-round-toggle")
                chk.grid(row=row + 1, column=col, padx=5, pady=2, sticky="w")

        def toggle_all(self):
            state1 = self.select_all_var1.get()
            for var in self.vars:
                var.set(state1)

        def toggle_all_and_disable(self):
            state2 = self.select_all_var2.get()
            for var in self.vars:
                var.set(state2)
            num_downloads_entry.config(state=tk.DISABLED if state2 else tk.NORMAL)

        def get_selected(self):
            """ Returns selected checkboxes, or 'all' if everything is selected """
            selected = [label for var, label in zip(self.vars[1:], self.options) if var.get()]
            return "all" if len(selected) + 1 == len(self.options) else selected

    labels = {
        "Tests": ["lsb", "jpeg", "image_integrity", "audio_integrity", "object_detection", "binary", "elf_check", "png",
                  "hist", "audio_detection"],
        "File Types": ["png", "jpg", "jpeg", "pdf", "docx", "mp3", "wav", "bin"]
    }

    groups = []
    for row, (title, options) in enumerate(labels.items()):
        groups.append(CheckboxGroup(inner_frame, title, options, row, 7 if row == 0 else 10))

    for i, (label_text, hint_text) in enumerate(fields):
        label = ttk.Label(inner_frame, text=label_text, font=("Arial", 11), foreground="#3498DB", background="#040D12")
        label.grid(row=i + 2, column=0, padx=0, pady=8, sticky="w")

        entry = ttk.Entry(inner_frame, width=40)
        entry.grid(row=i + 2, column=1, padx=0, pady=5, ipady=5)
        entry.insert(0, hint_text)
        entry.config(foreground="gray")
        entry.bind("<FocusIn>", lambda e, entry=entry, hint_text=hint_text: remove_hint(entry, hint_text))
        entry.bind("<FocusOut>", lambda e, entry=entry, hint_text=hint_text: add_hint(entry, hint_text))
        entry.bind("<<Paste>>", lambda e, entry=entry, hint_text=hint_text: handle_input_change(entry, hint_text))
        entry.bind("<KeyRelease>", lambda e, entry=entry, hint_text=hint_text: handle_input_change(entry, hint_text))


        add_context_menu(entry)

        entries.append(entry)

    output_entry, local_entry, num_downloads_entry = entries[4], entries[5], entries[2]

    ttk.Button(inner_frame, text="Browse", command=select_output_dir, bootstyle="info-outline", width=12).grid(row=6,
                                                                                                               column=2,
                                                                                                               padx=8)
    ttk.Button(inner_frame, text="Browse", command=select_local_file, bootstyle="info-outline", width=12).grid(row=7,
                                                                                                               column=2,
                                                                                                               padx=8)

    submit_btn = ttk.Button(inner_frame, text="Submit", command=lambda: run_start_progress_threaded(), bootstyle="success-outline",
                            width=16)  # need to also get the checkbox results
    submit_btn.grid(row=10, column=0, columnspan=3, pady=15)

    # Progress Bar Section (Initially Hidden)
    progress_frame = ttk.Frame(inner_frame)  # Now correctly placed inside main_frame
    progress_bar = ttk.Progressbar(progress_frame, mode="determinate", length=500, bootstyle="info-striped")
    progress_label = ttk.Label(progress_frame, text="Processing...", bootstyle="info", background="#040D12")
    
    def run_start_progress_threaded():
        thread = threading.Thread(target=start_progress, daemon=True)
        thread.start()

    def start_progress():
        global results_folder
        """ Starts the progress bar """
        progress_frame.grid(row=len(labels) + 9, column=0, columnspan=3,
                            pady=10)  # Show progress bar BELOW the submit button
        progress_bar.grid(row=0, column=0, padx=10, pady=5)
        progress_label.grid(row=1, column=0, padx=10, pady=5)
        progress_bar["value"] = 0
    
        # Collect selected options from each group
        results = {group.frame.cget("text"): group.get_selected() for group in groups}

        # Print checkbox selections
        # print("Selected Values:", results)
        test_modes = results["Tests"]
        file_types = "*" if results["File Types"] == "all" else results["File Types"]
        # print(test_modes)
        # print(file_types)

        # Collect entry values while filtering out hint text
        values = [entry.get() if entry.get() not in [field[1] for field in fields] else "" for entry in entries]
        # print("Submitted Values:", values)
        url = [values[0]]
        #print("here")
        ip = values[1]
        #print("here")
        num_files = values[2]
        #print("here")
        max_depth = int(values[3]) if values[3] != '' else 0
        #print("here")
        output_dir = values[4]
        #print("here")
        local_dir = values[5]
        #print("here")
        #print(url, ip, num_files, max_depth, output_dir, local_dir)
        
        #num_files = 10 if num_files == '' else int(num_files)


        # TODO MAKE IT RUN THE TEST NOW
        # output_dir = os.path.abspath(args.output)
        os.makedirs(output_dir, exist_ok=True)

        if local_dir != '':
            print("IN LOCAL")
            copy_local_files(local_dir, output_dir)

        #print("URL NULL: ", url != "", type(url))

        if url != "":
            #print("IN URL")
            sources = []
            for u in url:
                if re.match(r'\d+\.\d+\.\d+\.\d+', u):  # Single IP
                    if is_web_server(u):
                        sources.append(f"http://{u}/")
                elif re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', u):  # IP range
                    sources.extend([f"http://{ip}/" for ip in process_ip_range(u)])
                else:
                    sources.append(u if u.startswith("http") else f"http://{u}/")
            #print("PAST IP")

            threads = []
            temp_file_types = file_types.lower().split(',') if file_types != '*' else []
            #print("PAST TYPES")

            # For some reason this is not running, only dif is the output_dir is full path
            source_count = 0
            for source in sources:
                #update_progress(source_count, len(sources))
                source_count += 1
                thread = threading.Thread(target=threaded_download,
                                          args=(source, temp_file_types, num_files, file_types == '*', output_dir, set(), max_depth))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

        pdf_dir = os.path.join(output_dir, "pdf")
        docx_dir = os.path.join(output_dir, "docx")
        if os.path.exists(pdf_dir) or os.path.exists(docx_dir):
            # if "pdf" in file_types or "docx" in file_types:
            # print("IN TYPES CHECK")
            extract_from_file(output_dir)
            # pass

        jpeg_dir = os.path.join(output_dir, "jpeg")
        if os.path.exists(jpeg_dir):
            jpg_dir = os.path.join(output_dir, "jpg")
            os.makedirs(jpg_dir, exist_ok=True)
            for filename in os.listdir(jpeg_dir):
                f = os.path.join(jpeg_dir, filename)
                # checking if it is a file
                if os.path.isfile(f):
                    #print(f)
                    image_path = f
                    #print(f"{jpg_dir}/{filename}")
                    shutil.copy(image_path, f"{jpg_dir}/{filename}")
        # shutil.copytree(jpeg_dir, jpg_dir, dirs_exist_ok=True)

        process_images(output_dir)
        
        clean_up_folder(output_dir)

        # Generate a unique folder name using the current timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_folder_tmp = f"results_{timestamp}"

        # Create the unique results folder if it doesn't exist
        results_folder = os.path.join(output_dir, results_folder_tmp)
        os.makedirs(results_folder, exist_ok=True)

        all_test = test_modes == "all"
        
        #print("OUTOUT DIR IS HERE:", output_dir)

        # Mapping test modes to their respective functions
        mode_actions = {
            "lsb": lambda: t_lsb(output_dir),
            "image_integrity": lambda: image_integrity(output_dir),
            "hist": lambda: hist(output_dir),
            "object_detection": lambda: object_detection(output_dir),
            "jpeg": lambda: jpeg(output_dir),
            "png": lambda: png(output_dir),
            "audio_integrity": lambda: audio_integrity(output_dir),
            "audio_dectection": lambda: audio_dectection(output_dir),
            "binary": lambda: binary(output_dir),
            #"elf_check": lambda: elf_check(output_dir),
        }
        
        test_count = 0
        if "all" in test_modes:
            # print("we are in all")
            # Run all tests once and exit
            for action in mode_actions.values():  # for some reason we are getting stuck here
                # print(test_count, len(mode_actions.values()))
                update_progress(test_count, len(mode_actions.values()))
                test_count += 1
                action()
            open_directory(results_folder)
            update_progress(test_count, len(test_modes))
            test_count += 1
            
        else:
            for mode in test_modes:
                action = mode_actions.get(mode)
                if action:
                    # print("WE ARE IN ACTION")
                    update_progress(test_count, len(test_modes))
                    test_count += 1
                    action()
                else:
                    prRed(f"INVALID TEST MODE: {mode}")
            open_directory(results_folder)
            update_progress(test_count, len(test_modes))
            test_count = 0


    def update_progress(current_value, max_value):
        """ Updates progress bar smoothly over 10 seconds """
        if current_value < max_value:
            # current_value += 1
            current_percentage = ((current_value) / max_value) * 100
            progress_bar["value"] = current_percentage
            #root.after(max_value, update_progress, current_value)  # Update every 100ms (10s total)
            root.update_idletasks()
        else:
            progress_frame.grid_forget()  # Hide after completion

    root.mainloop()


def main():
    global results_folder
    parser = argparse.ArgumentParser(description="Download specific or all file types from a webpage.")
    parser.add_argument('-u', '--url', nargs='+',
                        help="Base URL(s), IP address(es), or IP range(s) to scrape files from")
    parser.add_argument('-t', '--types',
                        help="Comma-separated list of file extensions (e.g., pdf,jpg,png) or '*' for all files")
    parser.add_argument('-n', '--num', type=int, default=10,
                        help="Number of files to download (ignored if '-t *' is used)")
    parser.add_argument('-o', '--output', help="Directory to save downloaded files")
    parser.add_argument('-m', '--mode',
                        help="Test mode: specify test case(s) (e.g., lsb,hist) or 'all' to run all tests")
    parser.add_argument('-l', '--local', help="Path to a local file or directory to copy into the output directory")
    parser.add_argument('--max_depth', type=int, default=1, help="Maximum depth of the crawl (default is 1)")
    args = parser.parse_args()

    # Make sure all tools are installed here
    if platform.system() == "Windows":
        return

    elif platform.system() == "Linux":
        print("Installing tools on Linux...")
        install_commands = [
            "sudo apt update -y > /dev/null 2>&1",
            "sudo apt install -y stegdetect ruby binwalk exiftool steganography stego-rat stegosuite john > /dev/null 2>&1",
            "sudo gem install zsteg stegseek > /dev/null 2>&1"
        ]
        for command in install_commands:
            result = run_silent_command(command)
            if result:
                prGreen(f"Success: {command}")
            else:
                prRed(f"Failure: {command}")
        check_and_install_poppler()
        # print("All tools installed successfully on Linux!")

    if len(sys.argv) == 1:
        print("No arguments provided. Load GUI...")
        create_gui()
    else:
        output_dir = os.path.abspath(args.output)
        os.makedirs(output_dir, exist_ok=True)

        if args.local:
            copy_local_files(args.local, output_dir)
            
        #print("URL NULL: ", args.url != "", type(args.url))

        if args.url:
            sources = []
            for u in args.url:
                if re.match(r'\d+\.\d+\.\d+\.\d+', u):  # Single IP
                    if is_web_server(u):
                        sources.append(f"http://{u}/")
                elif re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', u):  # IP range
                    sources.extend([f"http://{ip}/" for ip in process_ip_range(u)])
                else:
                    sources.append(u if u.startswith("http") else f"http://{u}/")

            threads = []
            file_types = args.types.lower().split(',') if args.types != '*' else []

            for source in sources:
                thread = threading.Thread(target=threaded_download,
                                          args=(source, file_types, args.num, args.types == '*', args.output, set(),
                                                args.max_depth))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

        file_types = args.types.lower().split(',')

        pdf_dir = os.path.join(output_dir, "pdf")
        docx_dir = os.path.join(output_dir, "docx")
        if os.path.exists(pdf_dir) or os.path.exists(docx_dir):
            # if "pdf" in file_types or "docx" in file_types:
            # print("IN TYPES CHECK")
            extract_from_file(output_dir)
            # pass

        jpeg_dir = os.path.join(output_dir, "jpeg")
        if os.path.exists(jpeg_dir):
            jpg_dir = os.path.join(output_dir, "jpg")
            os.makedirs(jpg_dir, exist_ok=True)
            for filename in os.listdir(jpeg_dir):
                f = os.path.join(jpeg_dir, filename)
                # checking if it is a file
                if os.path.isfile(f):
                    #print(f)
                    image_path = f
                    #print(f"{jpg_dir}/{filename}")
                    shutil.copy(image_path, f"{jpg_dir}/{filename}")
        # shutil.copytree(jpeg_dir, jpg_dir, dirs_exist_ok=True)

        process_images(output_dir)
        
        clean_up_folder(output_dir)

        # Generate a unique folder name using the current timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_folder_tmp = f"results_{timestamp}"

        # Create the unique results folder if it doesn't exist
        results_folder = os.path.join(output_dir, results_folder_tmp)
        os.makedirs(results_folder, exist_ok=True)

        all_test = args.mode == "all"
        test_modes = "all" if all_test else args.mode.lower().split(',')
        
        #print("OUTOUT DIR IS HERE:", output_dir)

        # Mapping test modes to their respective functions
        mode_actions = {
            "lsb": lambda: t_lsb(output_dir),
            "image_integrity": lambda: image_integrity(output_dir),
            "hist": lambda: hist(output_dir),
            "object_detection": lambda: object_detection(output_dir),
            "jpeg": lambda: jpeg(output_dir),
            "png": lambda: png(output_dir),
            "audio_integrity": lambda: audio_integrity(output_dir),
            "audio_dectection": lambda: audio_dectection(output_dir),
            "binary": lambda: binary(output_dir),
            "elf_check": lambda: elf_check(output_dir),
        }

        if "all" in test_modes:
            # print("we are in all")
            # Run all tests once and exit
            for action in mode_actions.values():
                action()
            #return
        else:
            for mode in test_modes:
                action = mode_actions.get(mode)
                if action:
                    action()
                else:
                    prRed(f"INVALID TEST MODE: {mode}")
                    
        open_directory(results_folder)

    prGreen("done")


if __name__ == "__main__":
    #print(len(sys.argv))
    # sudo python StegoScan.py -u "https://www.uah.edu" -t "pdf,jpg,png" -n 1 -o "downloads" -m "all"
    # sudo python StegoScan.py -l "downloads" -t "*" -n 1 -o "downloads" -m "all"
    # sudo python StegoScan.py -u "https://en.wikipedia.org/wiki/Steganography" -t "*" -o "Out" -m "all" --max_depth 0
    # sudo python StegoScan.py -u "https://en.wikipedia.org/wiki/Steganography" -t "*" -o "/home/kali/Desktop/output_test" -m "all" --max_depth 0
    # sudo python StegoScan.py -l "output_test" -t "*" -n 1 -o "output_test" -m "png"

    # save download history to a txt, scan your own google drive?

    # try doing the language detection in chatGPT or aws

    # add in an output for detections and not etc for each test

    # add in levels of verbosity
    
    # fix local directory for gui

    main()
