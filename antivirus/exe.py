from tkinter import *
from tkinter import filedialog, messagebox  # Import messagebox
import requests
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import PageBreak
import time
import subprocess

api_key = '5b3860f88ce54fca6b8751e57ad817c08c2c98bd0e8b8be3e3988670a1b5bd87'  # Replace with your VirusTotal API key

def show_info_popup(title, message):
    messagebox.showinfo(title, message)

def scan_file_with_virustotal(file_path):
    try:
        if not file_path.endswith('.exe'):
            show_info_popup("Error", "Only .exe files are supported for scanning.")
            return None

        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            params = {'apikey': api_key}
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
            result = response.json()

            if result['response_code'] == 1:
                scan_id = result['scan_id']
                show_info_popup("Success", f"File scan successfully submitted. Scan ID: {scan_id}")
                return scan_id
            else:
                show_info_popup("Error", "File scan submission failed.")
                return None
    except Exception as e:
        show_info_popup("Error", f"An error occurred during file submission: {str(e)}")
        return None

def get_scan_results(scan_id):
    try:
        if scan_id is None:
            show_info_popup("Error", "No scan ID to retrieve results.")
            return

        params = {'apikey': api_key, 'resource': scan_id}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        result = response.json()

        while result['response_code'] != 1:
            show_info_popup("Info", f"Waiting for the scan report for '{scan_id}'...")
            time.sleep(30)  # Wait for 30 seconds before checking again
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            result = response.json()

        return result

    except Exception as e:
        show_info_popup("Error", f"An error occurred during results retrieval: {str(e)}")
        return None

def browse_file():
    file_path = filedialog.askopenfilename()
    file_text.delete(1.0, END)
    file_text.insert(1.0, file_path)

def scan_button_clicked():
    file_to_scan = file_text.get("1.0", "end-1c")
    if os.path.isfile(file_to_scan):
        scan_id = scan_file_with_virustotal(file_to_scan)
        if scan_id:
            scan_results = get_scan_results(scan_id)
            if scan_results is not None:
                save_results_to_pdf(scan_results)  # Save the results to a PDF
    else:
        show_info_popup("Error", "The specified file does not exist.")

def save_results_to_pdf(scan_results):
    if 'scans' not in scan_results:
        show_info_popup("Info", "No scan results found for the given scan ID.")
        return

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate("scan_results_exe.pdf", pagesize=letter)
    story = []

    # Title
    title = "VirusTotal Scan Report"
    story.append(Paragraph(title, styles['Title']))
    story.append(Spacer(1, 12))

    # Details
    details = f"Scan ID: {scan_results['scan_id']}"
    story.append(Paragraph(details, styles['Normal']))
    story.append(Spacer(1, 12))

    # Scan Results
    scan_results_table = []
    for scanner, scan_info in scan_results['scans'].items():
        result = scan_info['result']
        scan_results_table.append([scanner, result])

    table_style = TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                             ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                             ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                             ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                             ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                             ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                             ('GRID', (0, 0), (-1, -1), 1, colors.black)])

    scan_results_table.insert(0, ['Scanner', 'Result'])
    t = Table(scan_results_table)
    t.setStyle(table_style)
    story.append(t)

    doc.build(story)
    show_info_popup("Info", "PDF saved as scan_results_exe.pdf")
    subprocess.Popen(['start', 'scan_results_exe.pdf'], shell=True)

window = Tk()
window.title("EXE Scanner")
window.geometry("850x850")

winFrame = Frame(window, width="850", height="850", bg="Lightblue1")
winFrame.pack()
winFrame.pack_propagate(0)

global logoLabelImg
logoLabelImg = PhotoImage(file='Anti\\image\\logo.png')
logoLabel = Label(winFrame, image=logoLabelImg, bg='Lightblue1')
logoLabel.place(x=10, y=0)

# Label
upload_label = Label(winFrame, text="Upload a File", font=("Terminal", 30, "bold"), bg="Lightblue1", fg="slate gray")
upload_label.place(x=250, y=200)

# Browse button
browse_button = Button(winFrame, text="Browse", font=("Centaur", 20), bg="aquamarine", fg="slate gray", command=browse_file)
browse_button.place(x=137, y=350, height=50)

# File text entry
file_text = Text(winFrame, width=40, height=2.4, font=("Courier", 15))
file_text.place(x=250, y=350)

# Scan button
scan_button = Button(winFrame, text="Scan File", font=("Centaur", 25), bg="aquamarine", fg="slate gray", command=scan_button_clicked)
scan_button.place(x=350, y=450)

window.mainloop()
