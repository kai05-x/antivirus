import requests
from tkinter import *
from tkinter import font
from fpdf import FPDF
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import subprocess

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Replace with your own VirusTotal API key
api_key = 'with_your_api_key'

class PDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_font('Helvetica', 'B', 12)

    def chapter_title(self, title):
        self.set_font('Helvetica', 'B', 12)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(10)

    def chapter_body(self, body):
        self.set_font('Helvetica', '', 12)
        self.multi_cell(0, 10, body)
        self.ln()

def save_results_to_pdf(scan_id, scan_results):
    try:
        if scan_results is None:
            print("No scan results to save.")
            return

        pdf = PDF()
        pdf.add_page()
        pdf.chapter_title("Scan ID: " + scan_id)

        for key, value in scan_results.items():
            pdf.chapter_body(key + ": " + value)

        pdf_filename = "scan_results.pdf"
        pdf.output(pdf_filename)

        print("PDF saved as", pdf_filename)
    except Exception as e:
        print("An error occurred:", str(e))

def scan_url(url):
    try:
        params = {'apikey': api_key, 'url': url}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        result = response.json()

        if result['response_code'] == 1:
            scan_id = result['scan_id']
            print(f"URL scan successfully submitted. Scan ID: {scan_id}")
            return scan_id  # Return the scan ID
        else:
            print("URL scan submission failed.")
            return None
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def get_scan_results(scan_id):
    try:
        if scan_id is None:
            print("No scan ID to retrieve results.")
            return

        params = {'apikey': api_key, 'resource': scan_id}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        result = response.json()

        if result['response_code'] == 1:
            scan_results = {
                "Scan Date": result['scan_date'],
                "Total Scanners": str(result['total']),
                "Positive Scanners": str(result['positives'])
            }
            scan_results_table = []

            for scanner, scan_info in result['scans'].items():
                result = scan_info['result']
                if result.lower() == "malicious site" or result.lower() == "unrated site":
                    scan_results_table.append([scanner, result])
                else:
                    scan_results_table.append([scanner, ""])

            if not scan_results_table:
                print("No malicious or unrated sites detected.")
                return

            save_results_to_pdf(scan_id, scan_results, scan_results_table)
        else:
            print("No scan results found for the given scan ID.")
    except Exception as e:
        print("An error occurred:", str(e))



def save_results_to_pdf(scan_id, scan_results, scan_results_table):
    try:
        doc = SimpleDocTemplate("scan_results_url.pdf", pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title = "VirusTotal Scan Report"
        story.append(Paragraph(title, styles['Title']))
        story.append(Spacer(1, 12))

        # Details
        details = f"Scan ID: {scan_id}"
        story.append(Paragraph(details, styles['Normal']))
        story.append(Spacer(1, 12))

        # Scan Results
        scan_results_table.insert(0, ['Scanner', 'Result'])
        t = Table(scan_results_table)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(t)

        doc.build(story)
        subprocess.Popen(['start', 'scan_results_url.pdf'], shell=True)
    except Exception as e:
        print("An error occurred:", str(e))

# tkinter GUI
window = Tk()
window.title("URL Scanner")
window.geometry("850x850")
window.minsize("850", "850")
window.maxsize("850", "850")

winFrame = Frame(window, width="850", height="850", bg="skyblue1")
winFrame.pack()
winFrame.pack_propagate(0)

title_bar = Frame(window, bg='skyblue1', relief='raised')
title_bar.pack(expand=1, fill=X)

# Logo
global logoLabelImg
logoLabelImg = PhotoImage(file='Anti\\image\\logo.png')
logoLabel = Label(winFrame, image=logoLabelImg, bg='skyblue1')
logoLabel.place(x=10, y=0)

# Enter a URL Label
enter_url_label = Label(winFrame, text="Enter a URL", font=("Terminal", 30, "bold"), bg="skyblue1", fg="white")
enter_url_label.place(x=290, y=200)

# Textbox for URL
url_entry = Entry(winFrame, width=20, font=("Courier", 30))
url_entry.place(x=250, y=300)

def scan_button_clicked():
    url_to_scan = url_entry.get()
    scan_id = scan_url(url_to_scan)  # Capture the scan ID
    get_scan_results(scan_id)  # Use the captured scan ID for retrieval

# Scan Button
scan_button = Button(winFrame, text="Scan URL", font=("Centaur", 25), bg="limegreen", fg="white", command=scan_button_clicked)
scan_button.place(x=350, y=400)

window.mainloop()
