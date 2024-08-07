import tkinter as tk
from tkinter import filedialog
from Cryptodome.Cipher import AES
from Cryptodome import Random
import base64
import hashlib
import os

# Function to get the file path for opening a file
def open_file_dialog():
    file_path = filedialog.askopenfilename()
    return file_path

# Function to get the file path for saving a file
def save_file_dialog():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    return file_path

# AES encryption function
def encrypt_AES(key, inputFile, outputFile=None):
    if not os.path.exists(inputFile):
        message_label.config(text="Invalid file path")
        return

    chunkSize = 64 * 1024
    outputFile = inputFile + ".enc"

    # Get the file size
    filesize = str(os.path.getsize(inputFile)).zfill(16)

    IV = Random.new().read(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(inputFile, 'rb') as inFile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = inFile.read(chunkSize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))

    os.remove(inputFile)

# AES decryption function
def decrypt_AES(inputFile, key, outputFile=None):
    if not os.path.exists(inputFile):
        message_label.config(text="Invalid file path")
        return

    chunkSize = 64 * 1024
    outputFile = inputFile[:-4]

    with open(inputFile, 'rb') as inFile:
        filesize = int(inFile.read(16))
        IV = inFile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outFile:
            while True:
                chunk = inFile.read(chunkSize)
                if len(chunk) == 0:
                    break
                outFile.write(decryptor.decrypt(chunk))
            outFile.truncate(filesize)

    os.remove(inputFile)

# Function for encryption using a custom algorithm
def ownAlgoEncrypt(file_path, key):
    with open(file_path, 'rb') as file:
        content = file.read()

    encrypted_data = bytearray()
    key_length = len(key)
    for byte in content:
        encrypted_byte = (byte ^ key[key_length % key_length])
        encrypted_data.append(encrypted_byte)

    output_file = file_path + ".enc"

    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

    textbox1.delete("1.0", "end")
    textbox1.insert("end", content.decode("utf-8"))

    textbox2.delete("1.0", "end")
    textbox2.insert("end", encrypted_data.decode("utf-8"))

    message_label.config(text="File encrypted successfully.")
    os.remove(file_path)

# Function for decryption using a custom algorithm
def ownAlgoDecrypt(file_path, key):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()

        decrypted_data = bytearray()
        key_length = len(key)
        for byte in content:
            decrypted_byte = (byte ^ key[key_length % key_length])
            decrypted_data.append(decrypted_byte)

        output_file = file_path[:-4]

        with open(output_file, 'wb') as file:
            file.write(decrypted_data)

        textbox1.delete("1.0", "end")
        textbox1.insert("end", content.decode("utf-8"))

        textbox2.delete("1.0", "end")
        textbox2.insert("end", decrypted_data.decode("utf-8"))

        message_label.config(text="File decrypted successfully.")
    except FileNotFoundError:
        message_label.config(text="File not found.")
    except Exception as e:
        message_label.config(text="An error occurred during decryption: " + str(e))

# Function to handle the encrypt button click
def on_encrypt_button_click():
    key = key_entry.get()
    file_path = open_file_dialog()

    key = key.encode('utf-8')
    hashed_bytes = hashlib.sha256(key).digest()[:16]
    key = base64.urlsafe_b64encode(hashed_bytes)

    selectedRadioBtn = selected_value.get()
    if selectedRadioBtn == "AES":
        encrypt_AES(key, file_path)
    else:
        ownAlgoEncrypt(file_path, key)

    message_label.config(text="File encrypted successfully.")

# Function to handle the decrypt button click
def on_decrypt_button_click():
    key = key_entry.get()
    file_path = open_file_dialog()

    key = key.encode('utf-8')
    hashed_bytes = hashlib.sha256(key).digest()[:16]
    key = base64.urlsafe_b64encode(hashed_bytes)

    selectedRadioBtn = selected_value.get()
    if selectedRadioBtn == "AES":
        decrypt_AES(file_path, key)
    else:
        ownAlgoDecrypt(file_path, key)

    message_label.config(text="File decrypted successfully.")

# Create the GUI window
root = tk.Tk()
root.title("File Encrypter")
root.geometry("500x320")

lblIntro = tk.Label(root, text="ENCRYPT OR DECRYPT ANY FILE", font=("Arial", 18))
lblIntro.pack(pady=20)

algorithm_frame = tk.Frame(root)
algorithm_frame.pack()

lblSelect = tk.Label(algorithm_frame, text="Please select an algorithm:", font=("Arial", 14))
lblSelect.pack(side=tk.LEFT, padx=10)

selected_value = tk.StringVar(value="AES")
radio_button_1 = tk.Radiobutton(algorithm_frame, text="AES", variable=selected_value, value="AES", font=("Arial", 14))
radio_button_2 = tk.Radiobutton(algorithm_frame, text="OurAlgo", variable=selected_value, value="OurAlgo", font=("Arial", 14))

radio_button_1.pack(side=tk.LEFT, padx=10)
radio_button_2.pack(side=tk.LEFT, padx=10)

key_frame = tk.Frame(root)
key_frame.pack(pady=20)

label2 = tk.Label(key_frame, text="Enter the encryption key:", font=("Arial", 14))
label2.pack(side=tk.LEFT, padx=10)

key_entry = tk.Entry(key_frame, show="*")
key_entry.pack(side=tk.LEFT, padx=10)

button_frame = tk.Frame(root)
button_frame.pack(pady=20)

button1 = tk.Button(button_frame, text="Encrypt File", command=on_encrypt_button_click, font=("Arial", 12), relief="groove", borderwidth=2, fg="white", bg="green")
button1.pack(side=tk.LEFT, padx=10)

button2 = tk.Button(button_frame, text="Decrypt File", command=on_decrypt_button_click, font=("Arial", 12), relief="groove", borderwidth=2, fg="white", bg="red")
button2.pack(side=tk.LEFT, padx=10)

textbox1 = tk.Text(root, height=7, width=30)
textbox1.pack(side=tk.LEFT, padx=10, pady=10)
textbox2 = tk.Text(root, height=7, width=30)
textbox2.pack(side=tk.RIGHT, padx=10, pady=10)

message_frame = tk.Frame(root)
message_frame.pack(pady=20)

message_label = tk.Label(message_frame, text="", font=("Arial", 12))
message_label.pack()

root.mainloop()
