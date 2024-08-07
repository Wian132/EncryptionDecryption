import PySimpleGUI as sg

# Define the layout of the GUI
layout = [
    [sg.Text('File'), sg.Input(key='-FILE-'), sg.FileBrowse()],
    [sg.Text('Method:')],
    [sg.Radio('Vigenere', 'METHOD', key='-VIGENERE-'), sg.Radio('Vernam', 'METHOD', key='-VERNAM-'), 
     sg.Radio('Transposition', 'METHOD', key='-TRANSPOSITION-'), sg.Radio('OwnAlg', 'METHOD', key='-OWNALG-')],
    [sg.Text('Key:'), sg.Input(key='-KEY-')],
    [sg.Radio('Encrypt', 'ACTION', key='-ENCRYPT-'), sg.Radio('Decrypt', 'ACTION', key='-DECRYPT-')],
    [sg.Text('Input:'), sg.Multiline(key='-INPUT-', size=(50, 5)), sg.Text('Output:'), sg.Multiline(key='-OUTPUT-', size=(50, 5))],
    [sg.Button('Run', key='-RUN-'), sg.Button('Close', key='-CLOSE-', button_color=('white', 'red'))]
]

# Create the window with the defined layout
window = sg.Window('My GUI', layout)

# Event loop to process events and get input from the user
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == '-CLOSE-':
        break
    if event == '-RUN-':
        # Get the values from the input fields
        file_path = values['-FILE-']
        method = None
        if values['-VIGENERE-']:
            method = 'Vigenere'
        elif values['-VERNAM-']:
            method = 'Vernam'
        elif values['-TRANSPOSITION-']:
            method = 'Transposition'
        elif values['-OWNALG-']:
            method = 'OwnAlg'
        key = values['-KEY-']
        action = 'Encrypt' if values['-ENCRYPT-'] else 'Decrypt'
        input_text = values['-INPUT-']
        
        # TODO: perform the encryption/decryption operation with the selected method, key, and action
        
        # Update the output field with the result
        window['-OUTPUT-'].update(output_text)

# Close the window and exit the program
window.close()
