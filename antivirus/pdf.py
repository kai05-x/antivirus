import requests
from tkinter import *
from tkinter import filedialog, messagebox
from fpdf import FPDF
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import warnings
import time
import yara

# Function to scan the selected PDF file
def scan_pdf():
    file_path = file_text.get("1.0", "end-1c").strip()

    # Check if a file path is provided
    if not file_path:
        messagebox.showerror("Error", "Please select a PDF file.")
        return
    
    try:
        # Perform YARA rule-based malware scanning
        yara_rule_file = "D:\\malware-analyser-main\\BitLink\\Anti\\pdf_rule.yara"  # Update with your YARA rule file path
        rules = yara.compile(filepath=yara_rule_file)

        with open(file_path, 'rb') as pdf_file:
            pdf_data = pdf_file.read()

        matches = rules.match(data=pdf_data)

        if matches:
            # Construct message with matched rules
            alert_message = "Malware detected in the PDF file!\n\nMatched rules:\n"
            for match in matches:
                alert_message += f"- {match.rule}\n"
            
            messagebox.showinfo("Malware Detected", alert_message)
        else:
            messagebox.showinfo("No Malware Detected", "No malware detected in the PDF file.")
    
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during scanning: {str(e)}")



# UI setup
window = Tk()
window.title("PDF Scanner")
window.geometry("850x850")

winFrame = Frame(window, width="850", height="850", bg="light blue")
winFrame.pack()
winFrame.pack_propagate(0)

# Logo
logoLabelImg = PhotoImage(file='Anti\\image\\logo.png')
logoLabel = Label(winFrame, image=logoLabelImg, bg='light blue')
logoLabel.place(x=10, y=0)

# Label
upload_label = Label(winFrame, text="Upload a PDF", font=("Terminal", 30, "bold"), bg="light blue", fg="snow")
upload_label.place(x=240, y=200)

# Browse button
def browse_pdf():
    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if file_path:
        file_text.delete(1.0, END)
        file_text.insert(1.0, file_path.replace('/', '\\'))


browse_button = Button(winFrame, text="Browse", font=("Centaur", 20), bg="light sea green", fg="snow", command=browse_pdf)
browse_button.place(x=137, y=350, height=50)

# File text entry
file_text = Text(winFrame, width=40, height=2.4, font=("Courier", 15))
file_text.place(x=250, y=350)

# Scan button
scan_button = Button(winFrame, text="Scan PDF", font=("Centaur", 25), bg="light sea green", fg="snow", command=scan_pdf)
scan_button.place(x=350, y=450)

window.mainloop()
