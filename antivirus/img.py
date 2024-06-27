import requests
from tkinter import *
from tkinter import filedialog, messagebox
from fpdf import FPDF
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import subprocess
import time 

# Replace with your own VirusTotal API key
api_key = 'replace_with_your_api'

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

def show_info_popup(title, message):
    messagebox.showinfo(title, message)

def scan_image_with_virustotal(image_path):
    try:
        valid_extensions = ('.png', '.jpg', '.jpeg', '.gif')
        if not image_path.lower().endswith(valid_extensions):
            show_info_popup("Error", f"Only {', '.join(valid_extensions)} files are supported for scanning.")
            return None

        with open(image_path, 'rb') as file:
            files = {'file': (image_path, file)}
            params = {'apikey': api_key}
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
            result = response.json()

            if result['response_code'] == 1:
                scan_id = result['scan_id']
                show_info_popup("Success", f"Image scan successfully submitted. Scan ID: {scan_id}")
                return scan_id
            else:
                show_info_popup("Error", "Image scan submission failed.")
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

        if result['response_code'] != 1:
            show_info_popup("Info", "Waiting for the scan report...")
            while result['response_code'] != 1:
                time.sleep(30)
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                result = response.json()

        if 'scans' not in result:
            show_info_popup("Info", "No scan results found for the given scan ID.")
            return

        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate("scan_results_IMG.pdf", pagesize=letter)
        story = []

        story.append(Paragraph("VirusTotal Scan Report", styles['Title']))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Scan ID: " + scan_id, styles['Normal']))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Scan Date: " + result['scan_date'], styles['Normal']))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Total Scanners: " + str(result['total']), styles['Normal']))
        story.append(Spacer(1, 12))
        story.append(Paragraph("Positive Scanners: " + str(result['positives']), styles['Normal']))
        story.append(Spacer(1, 12))

        scan_results_table = []

        for scanner, scan_info in result['scans'].items():
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
        show_info_popup("Info", "PDF saved as scan_results_IMG.pdf")
        subprocess.Popen(['start', 'scan_results_IMG.pdf'], shell=True)
    except Exception as e:
        show_info_popup("Error", "An error occurred during results retrieval: " + str(e))

def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif")])
    file_text.delete(1.0, END)
    file_text.insert(1.0, file_path)

def scan_file_button_clicked():
    file_to_scan = file_text.get("1.0", "end-1c")
    if file_to_scan.endswith(('.png', '.jpg', '.jpeg', '.gif')):
        scan_id = scan_image_with_virustotal(file_to_scan)
        if scan_id:
            get_scan_results(scan_id)
    else:
        show_info_popup("Error", "The specified file is not a PNG, JPG, JPEG, or GIF image.")

# GUI setup
window = Tk()
window.title("Image Scanner")
window.geometry("850x850")

winFrame = Frame(window, width="850", height="850", bg="deep sky blue")
winFrame.pack()
winFrame.pack_propagate(0)

# Logo
logoLabelImg = PhotoImage(file='Anti\\image\\logo.png')
logoLabel = Label(winFrame, image=logoLabelImg, bg='deep sky blue')
logoLabel.place(x=10, y=0)

# Label
upload_label = Label(winFrame, text="Upload an Image", font=("Terminal", 30, "bold"), bg="deep sky blue", fg="snow")
upload_label.place(x=240, y=200)

# Browse button
browse_button = Button(winFrame, text="Browse", font=("Centaur", 20), bg="light sea green", fg="snow", command=browse_file)
browse_button.place(x=137, y=350, height=50)

# File text entry
file_text = Text(winFrame, width=40, height=2.4, font=("Courier", 15))
file_text.place(x=250, y=350)

# Scan button
scan_button = Button(winFrame, text="Scan Image", font=("Centaur", 25), bg="light sea green", fg="snow", command=scan_file_button_clicked)
scan_button.place(x=350, y=450)

window.mainloop()
