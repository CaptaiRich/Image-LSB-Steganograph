from tkinter import *
from tkinter import ttk
import tkinter.filedialog
from PIL import ImageTk
from PIL import Image
from tkinter import messagebox
from io import BytesIO
import os
from Crypto.Cipher import AES
import hashlib
import base64

class Stegno:

    art2 = """
  ____ _  __ _______     _    _  _______  _     _____ 
 / ___| |/ /|__   __|   | |  | ||__   __|/ \   / ____|
| |   | ' /    | |  ----| |  | |   | |  / _ \  \___   
| |___| . \    | |  ----| |  | |   | | / ___ \  ___| |
 \____|_|\_\   |_|      \______/   |_|/_/   \_\|_____/
                                    
       ¯\_(ツ)_/¯  IMAGE STEGANOGRAPHY  ¯\_(ツ)_/¯
"""
    output_image_size = 0

    def main(self, stegoApp):
        stegoApp.title('20200404521 - Image Steganography')
        stegoApp.geometry('600x700')
        stegoApp.resizable(width=True, height=True)
        stegoApp.configure(bg="lightblue")
        f = Frame(stegoApp, bg='lightblue')

        ascii_art = Label(f, text=self.art2)
        ascii_art.config(font=('courier', 12, 'bold',), bg='lightblue',fg='maroon')

        btnEncode = Button(f, text="ENCODE", command=lambda: self.frameEncodeOne(f), padx=120, pady=16)
        btnEncode.config(font=('courier', 14, 'bold'), bg='red', fg='white')
        btnDecode = Button(f, text="DECODE", padx=120,pady=16, command=lambda: self.frameDecodeOne(f))
        btnDecode.config(font=('courier', 14, ''), bg="green", fg="white")
        btnDecode.grid(pady=12)

        stegoApp.grid_rowconfigure(1, weight=1)
        stegoApp.grid_columnconfigure(0, weight=1)
        
        f.grid()
        ascii_art.grid(row=1, pady=10)
        btnEncode.grid(row=2)
        btnDecode.grid(row=3)

    def home(self, frame):
        frame.destroy()
        self.main(stegoApp)

    def frameDecodeOne(self, f):
        f.destroy()
        d_f2 = Frame(stegoApp, bg='lightblue')
        label_art = Label(d_f2, text='SELECT STEGO IMAGE', bg='lightblue')
        label_art.config(font=('courier', 40, 'bold'))
        label_art.grid(row=1, pady=50)
        l1 = Label(d_f2, text='Select Image with Hidden text')
        l1.config(font=('courier', 12, 'bold'), bg='lightblue')
        l1.grid()
        btnBws = Button(d_f2, text='SELECT', command=lambda: self.frameDecodeTwo(d_f2), padx=100, pady=16)
        btnBws.config(font=('courier', 18, 'bold'), fg='white', bg='blue')
        btnBws.grid()
        btnBack = Button(d_f2, text='CANCEL', command=lambda: Stegno.home(self, d_f2), padx=100, pady=16)
        btnBack.config(font=('courier', 18, 'bold'), fg='white', bg='red')
        btnBack.grid(pady=15)
        btnBack.grid()
        d_f2.grid()

    def frameDecodeTwo(self, d_f2):
        d_f3 = Frame(stegoApp,bg='lightblue')
        myfile = tkinter.filedialog.askopenfilename(filetypes=([('png', '*.png'), ('jpeg', '*.jpeg'), ('jpg', '*.jpg'), ('All Files', '*.*')]))
        if not myfile:
            messagebox.showerror("Error", "You have selected nothing!")
        else:
            myimg = Image.open(myfile, 'r')
            myimage = myimg.resize((300, 200))
            img = ImageTk.PhotoImage(myimage)
            l4 = Label(d_f3, text='SELECTED STEGO IMAGE')
            l4.config(font=('courier', 18, 'bold'),bg='lightblue')
            l4.grid()
            panel = Label(d_f3, image=img)
            panel.image = img
            panel.grid()
            
            # Set attributes for info method
            self.output_image_size = os.stat(myfile)
            self.o_image_w, self.o_image_h = myimg.size
            self.m_image_size = self.output_image_size 

            hidden_data = self.decode(myimg)
            l2 = Label(d_f3, text='Secret Message is')
            l2.config(font=('courier', 18, 'bold'), bg='lightblue')
            l2.grid(pady=10)
            txtArea = Text(d_f3, width=50, height=10)
            txtArea.insert(INSERT, hidden_data)
            txtArea.configure(state='disabled')
            txtArea.grid()
            btnBack = Button(d_f3, text='CANCEL', command=lambda: self.page3(d_f3))
            btnBack.config(font=('courier', 18, 'bold'), padx=160,pady=16, fg='white', bg='red')
            btnBack.grid(pady=16)
            btnBack.grid()
            show_info = Button(d_f3, text='MORE INFO', command=self.info)
            show_info.config(font=('courier', 18, 'bold'), padx=140,pady=16, fg='white', bg='blue')
            show_info.grid()
            d_f3.grid(row=1)
            d_f2.destroy()

    def decode(self, image):
        data = ''
        imgdata = iter(image.getdata())
        while (True):
            pixels = [value for value in imgdata.__next__()[:3] +
                      imgdata.__next__()[:3] +
                      imgdata.__next__()[:3]]
            binstr = ''
            for i in pixels[:8]:
                if i % 2 == 0:
                    binstr += '0'
                else:
                    binstr += '1'

            data += chr(int(binstr, 2))
            if pixels[-1] % 2 != 0:
                break

        key = self.promptForKey()
        if key:
            try:
                decrypted_data = self.decrypt(data, key)
                return decrypted_data
            except:
                messagebox.showerror("Error", "Decryption failed. Incorrect key or corrupted data.")
                return ''

    def frameEncodeOne(self, f):
        f.destroy()
        f2 = Frame(stegoApp, bg='lightblue')
        label_art = Label(f2, text='SELECT COVER IMAGE')
        label_art.config(font=('courier', 40, 'bold'), bg='lightblue')
        label_art.grid(row=1, pady=50)
        l1 = Label(f2, text='Select the Image in which you \n want to embed your secret text\n')
        l1.config(font=('courier', 12, 'bold'), bg='lightblue')
        l1.grid()

        btnBws = Button(f2, text='SELECT', command=lambda: self.frameEncodeTwo(f2), padx=120, pady=16)
        btnBws.config(font=('courier', 18,'bold'), fg='white', bg='blue')
        btnBws.grid()
        btnBack = Button(f2, text='CANCEL', command=lambda: Stegno.home(self, f2), padx=120, pady=16)
        btnBack.config(font=('courier', 18,'bold'), fg='white', bg='red')
        btnBack.grid(pady=15)
        btnBack.grid()
        f2.grid()

    def frameEncodeTwo(self, f2):
        ep = Frame(stegoApp, bg='lightblue')
        myfile = tkinter.filedialog.askopenfilename(filetypes=([('png', '*.png'), ('jpeg', '*.jpeg'), ('jpg', '*.jpg'), ('All Files', '*.*')]))
        if not myfile:
            messagebox.showerror("Error", "You have selected nothing!")
        else:
            myimg = Image.open(myfile)
            myimage = myimg.resize((300, 200))
            img = ImageTk.PhotoImage(myimage)
            l3 = Label(ep, text='Selected Image')
            l3.config(font=('courier', 18,'bold'), bg='lightblue')
            l3.grid()
            panel = Label(ep, image=img)
            panel.image = img
            self.output_image_size = os.stat(myfile)
            self.o_image_w, self.o_image_h = myimg.size
            panel.grid()

            l2 = Label(ep, text='Enter the message')
            l2.config(font=('courier', 18, 'bold'),bg='lightblue')
            l2.grid(pady=15)
            text_area = Text(ep, width=50, height=5)
            text_area.grid()

            l3 = Label(ep, text='Enter Encryption Key')
            l3.config(font=('courier', 18, 'bold'), bg='lightblue')
            l3.grid(pady=15)
            key_entry = Entry(ep, show='*', width=50)
            key_entry.grid()

            btnBack = Button(ep, text='CANCEL', command=lambda: Stegno.home(self, ep))
            btnBack.config(font=('courier', 11,'bold'), bg='red', padx=175, fg='white')
            btnBack.grid(pady=15)

            btnEncode = Button(ep, text='ENCODE', command=lambda: [self.encodFunction(text_area, key_entry.get(), myimg), Stegno.home(self, ep)])
            btnEncode.config(font=('courier', 11,'bold'),bg='green', fg='white', padx=175)
            btnEncode.grid()

            ep.grid(row=1)
            f2.destroy()

    def encodFunction(self, text_area, key, myimg):
        data = text_area.get("1.0", "end-1c")
        if len(data) == 0:
            messagebox.showinfo("Alert", "Kindly enter text in TextBox")
        elif len(key) == 0:
            messagebox.showinfo("Alert", "Kindly enter an encryption key")
        else:
            encrypted_data = self.encrypt(data, key)
            newimg = myimg.copy()
            self.encode_enc(newimg, encrypted_data)
            temp = os.path.splitext(os.path.basename(myimg.filename))[0]
            save_filename = tkinter.filedialog.asksaveasfilename(initialfile=temp, filetypes=([('png', '*.png')]), defaultextension=".png")
            if save_filename:
                newimg.save(save_filename)
                messagebox.showinfo("Success", f"Encoding Successful\nFile is saved as {save_filename}")

    def encrypt(self, data, key):
        # Create a SHA-256 hash of the key
        key_hash = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key_hash, AES.MODE_ECB)
        padded_data = data + (16 - len(data) % 16) * ' '
        encrypted_data = cipher.encrypt(padded_data.encode())
        return base64.b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_data, key):
        key_hash = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key_hash, AES.MODE_ECB)
        decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
        return decrypted_data.decode().rstrip(' ')

    def encode_enc(self, newimg, data):
        w = newimg.size[0]
        (x, y) = (0, 0)

        for pixel in self.modPix(newimg.getdata(), data):
            newimg.putpixel((x, y), pixel)
            if x == w - 1:
                x = 0
                y += 1
            else:
                x += 1

    def modPix(self, pix, data):
        datalist = self.genData(data)
        lendata = len(datalist)
        imdata = iter(pix)

        for i in range(lendata):
            pix = [value for value in imdata.__next__()[:3] +
                   imdata.__next__()[:3] +
                   imdata.__next__()[:3]]

            for j in range(0, 8):
                if (datalist[i][j] == '0') and (pix[j] % 2 != 0):
                    if (pix[j] % 2 != 0):
                        pix[j] -= 1

                elif (datalist[i][j] == '1') and (pix[j] % 2 == 0):
                    pix[j] -= 1

            if (i == lendata - 1):
                if (pix[-1] % 2 == 0):
                    pix[-1] -= 1
            else:
                if (pix[-1] % 2 != 0):
                    pix[-1] -= 1

            pix = tuple(pix)
            yield pix[0:3]
            yield pix[3:6]
            yield pix[6:9]

    def genData(self, data):
        newd = []
        for i in data:
            newd.append(format(ord(i), '08b'))
        return newd

    def page3(self, frame):
        frame.destroy()
        self.main(stegoApp)

    def info(self):
        str = f"Original image: {self.o_image_w} x {self.o_image_h} pixels\n\n" \
              f"Original size: {self.output_image_size.st_size} bytes\n\n" \
              f"Modified image: {self.o_image_w} x {self.o_image_h} pixels\n\n" \
              f"Modified size: {self.m_image_size.st_size} bytes\n\n" \
              f"Ratio: {self.m_image_size.st_size / self.output_image_size.st_size}"
        messagebox.showinfo('Info', str)

    def promptForKey(self):
        key_window = Toplevel(stegoApp)
        key_window.title("Enter Decryption Key")
        key_window.geometry('300x150')
        Label(key_window, text="Enter Decryption Key:").pack(pady=10)
        key_entry = Entry(key_window, show='*', width=30)
        key_entry.pack(pady=10)
        key = None

        def on_ok():
            nonlocal key
            key = key_entry.get()
            key_window.destroy()

        Button(key_window, text="OK", command=on_ok).pack(pady=10)
        key_window.wait_window()
        return key

stegoApp = Tk()
o = Stegno()
o.main(stegoApp)
stegoApp.mainloop()