# antivirus

**Description**
Antivirus is a desktop application built using Python's Tkinter library. This application provides a user interface to scan files, images, executables, PDFs, and URLs for malware. It integrates with VirusTotal and YARA to perform scans and display results.


**Features**
`File Scanning`: Scan executable files for malware.

`Image Scanning`: Scan images (PNG, JPG, JPEG, GIF) for malware.

`PDF Scanning`: Scan PDF files using YARA rules.

`URL Scanning`: Scan URLs for potential threats.

`Real-time Animation`: Animated robot on the main interface.

**Prerequisites**
Python 3.x

Required Python libraries: subprocess, glob, tkinter, psutil, pystray, PIL, screeninfo, requests, reportlab, fpdf, yara

A valid VirusTotal API key

**File Structure**
main.py: The main application script.

scan_file.py: Script for scanning executable files.

scan_image.py: Script for scanning image files.

scan_pdf.py: Script for scanning PDF files.

scan_url.py: Script for scanning URLs.

requirements.txt: List of required packages.

images/: Directory containing image assets used in the application.

**Acknowledgements**
VirusTotal for their API.

YARA for their powerful pattern matching tool.

Tkinter for the GUI framework.
