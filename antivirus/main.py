import subprocess
from glob import glob
from tkinter import *
import psutil
import pystray
import PIL.Image
from screeninfo import get_monitors



window = Tk()

window.title("BitLink End-Point")
window.geometry("1200x850")
window.minsize("1200", "850")
window.maxsize("1200", "850")

winFrame = Frame(window, width="1200", height="850", bg="blue4")
winFrame.pack()
winFrame.pack_propagate(0)

title_bar = Frame(window, bg='gray17', relief='raised')
title_bar.pack(expand=1, fill=X)
global logoLabelImg
logoLabelImg = PhotoImage(file='D:\\malware-analyser-main\\BitLink\\Anti\image\\logo.png' )
logoLabel = Label(winFrame,image=logoLabelImg,bg='blue4')
logoLabel.place(x=10,y=0)

global nameLabelImg
nameLabelImg = PhotoImage(file='D:\\malware-analyser-main\\BitLink\\Anti\image\\b logo.png').subsample(2,2)
nameLabel = Label(winFrame,image=nameLabelImg,bg='blue4')
nameLabel.place(x=90,y=20)

# Load the robot image
robotImg = PhotoImage(file='D:\\malware-analyser-main\\BitLink\\Anti\image\\robotlink.png')

robotAnimation = Label(winFrame, image=robotImg, bg="blue4")
robotAnimation.place(x=405, y=150)

global ani
ani = 0

def RobotAnimation():
    global ani

    if ani == 4:
        robotAnimation.place_configure(y=153)
        ani = 0

    elif ani == 2:
        robotAnimation.place_configure(y=150)

    ani += 1

    robotAnimation.after(200, RobotAnimation)
    

RobotAnimation()

def open_url_py():
    subprocess.Popen(['python', 'D:\\malware-analyser-main\\BitLink\\Anti\\url.py'])

def open_pdf_py():
    subprocess.Popen(['python', 'D:\\malware-analyser-main\\BitLink\\Anti\\pdf.py'])   

def open_exe_py():
    subprocess.Popen(['python', 'D:\\malware-analyser-main\\BitLink\\Anti\\exe.py'])  

def open_img_py():
    subprocess.Popen(['python', 'D:\\malware-analyser-main\\BitLink\\Anti\\img.py'])      
          


urlimg = PhotoImage(file="D:\\malware-analyser-main\\BitLink\\Anti\\image\\url.png")
urlbutton = Label(winFrame,image=urlimg,bg="gray17",cursor="hand2")
urlbutton.place(x=220,y=570)
urlbutton.bind("<Button-1>", lambda event: open_url_py())


pdfImg = PhotoImage(file="D:\\malware-analyser-main\\BitLink\\Anti\\image\\pdf.png")
pdfbutton = Label(winFrame, image=pdfImg, bg="gray17", cursor="hand2")
pdfbutton.place(x=400, y=570)
pdfbutton.bind("<Button-1>", lambda event: open_pdf_py())


exeImg = PhotoImage(file="D:\\malware-analyser-main\\BitLink\\Anti\\image\\EXE.png")
exebutton = Label(winFrame,image=exeImg,bg="gray17",cursor="hand2")
exebutton.place(x=580,y=570)
exebutton.bind("<Button-1>", lambda event: open_exe_py())


photoImg = PhotoImage(file="D:\\malware-analyser-main\\BitLink\\Anti\\image\\photo.png")
photobutton = Label(winFrame,image=photoImg,bg="gray17",cursor="hand2")
photobutton.place(x=760,y=570)
photobutton.bind("<Button-1>", lambda event: open_img_py())



window.mainloop()


