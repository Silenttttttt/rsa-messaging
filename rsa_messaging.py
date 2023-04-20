
import base64
import tkinter as tk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import PySimpleGUI as sg

def copy_to_clipboard(text):
    clean_text = text.strip()
    root = tk.Tk()
    root.withdraw()
    root.clipboard_clear()
    root.clipboard_append(clean_text)
    root.update()
    root.destroy()
    

def paste_from_clipboard():
    root = tk.Tk()
    root.withdraw()
    text = root.clipboard_get()
    root.destroy()

    return text



def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('ascii')
    public_key = key.publickey().export_key().decode('ascii')
    return private_key, public_key


def encrypt_message(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode('ascii')

def decrypt_message(encrypted_message, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = base64.b64decode(encrypted_message.encode())
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

def derive_public_key_from_private_key(private_key):
    try:
        rsa_key = RSA.import_key(private_key)
        public_key = rsa_key.publickey().export_key().decode('ascii')
        return public_key
    except ValueError:
        return None

#
def main():
    custom_light_blue = ("#6699CC")
    custom_green = ("#4C8550")

    layout = [
        [sg.Text('Your Public Address:')],
        [sg.Multiline('', size=(80, 5), key='public_address', disabled=True),
        sg.Column([[sg.Button('Copy Public Address', button_color=('white', custom_light_blue))]])],
        [sg.Text('Private Key:')],
        [sg.Multiline('', size=(80, 5), key='private_key', enable_events=True),
        sg.Column([[sg.Button('Copy Private Key', button_color=('white', custom_light_blue))],
                    [sg.Button('Clear Private Key'), sg.Button('Paste Private Key', button_color=('white', custom_green))]])],
        [sg.Button('Generate Key Pair')],
        [sg.Text('Public Key To Encrypt Message:')],
        [sg.Multiline('', size=(80, 5), key='public_key'),
        sg.Column([[sg.Button('Copy Public Key', button_color=('white', custom_light_blue))],
                    [sg.Button('Clear Public Key'), sg.Button('Paste Public Key', button_color=('white', custom_green))]])],
        [sg.Text('Message To Encrypt/Decrypt:')],
        [sg.Multiline('', size=(80, 5), key='message'),
        sg.Column([[sg.Button('Copy Message', button_color=('white', custom_light_blue))],
                    [sg.Button('Clear Message'), sg.Button('Paste Message', button_color=('white', custom_green))]])],
        [sg.Text('Encrypted/Decrypted Message:')],
        [sg.Multiline('', size=(80, 5), key='encrypted_decrypted'),
        sg.Column([[sg.Button('Copy Message', button_color=('white', custom_light_blue))],
                    [sg.Button('Clear Message'), sg.Button('Paste Message', button_color=('white', custom_green))]])],
        [sg.Button('Encrypt'), sg.Button('Decrypt')]
    ]

    button_to_key_map = {
        'Copy Public Address': 'public_address',
        'Copy Private Key': 'private_key',
        'Paste Private Key': 'private_key',
        'Clear Private Key': 'private_key',
        'Copy Public Key': 'public_key',
        'Paste Public Key': 'public_key',
        'Clear Public Key': 'public_key',
        'Copy Message': 'message',
        'Paste Message': 'message',
        'Clear Message': 'message',
        'Copy Encrypted/Decrypted': 'encrypted_decrypted',
        'Paste Encrypted/Decrypted': 'encrypted_decrypted',
        'Clear Encrypted/Decrypted': 'encrypted_decrypted',
    }






    window = sg.Window('RSA Encryption/Decryption Messaging System', layout)

    while True:
            try:
                event, values = window.read()

                if event == sg.WIN_CLOSED:
                    break

                if event == 'Generate Key Pair':
                    private_key, public_key = generate_key_pair()
                  #  save_keys_to_file(private_key, public_key)
                    window['public_address'].update(public_key)
                    window['public_key'].update('')
                    window['private_key'].update(private_key)
                 #   window['message'].update('')
                   # window['encrypted_decrypted'].update('')
                    sg.popup('Key pair generated successfully!', title='Success', auto_close=True, auto_close_duration=2)

                if event == 'Encrypt':
                    if values['public_key'] and values['message']:
                        public_key = values['public_key'].strip()
                        message = values['message'].strip()
                        encrypted_message = encrypt_message(message, public_key)
                        window['encrypted_decrypted'].update(encrypted_message)
                    else:
                        sg.popup('Please enter public key and message.', title='Error', auto_close=True, auto_close_duration=2)

                if event == 'Decrypt':
                    if values['private_key'] and values['encrypted_decrypted']:
                        private_key = values['private_key'].strip()
                        encrypted_message = values['encrypted_decrypted'].strip()
                        decrypted_message = decrypt_message(encrypted_message, private_key)
                        window['encrypted_decrypted'].update(decrypted_message)
                    else:
                        sg.popup('Please enter private key and encrypted message.', title='Error', auto_close=True, auto_close_duration=2)

                if event in button_to_key_map:
                    key = button_to_key_map[event]

                
                if event.startswith('Copy '):
                    key = event[5:].lower().replace(' ', '_').replace('/', '_').replace("message0", "encrypted_decrypted")
                    copy_to_clipboard(values[key])
                    sg.popup('Copied to clipboard!', title='Success', auto_close=True, auto_close_duration=2)
                if event.startswith('Clear '):
                    key = event[6:].lower().replace(' ', '_').replace('/', '_').replace("message1", "encrypted_decrypted")##insane bug
                    window[key].update('')

                if event.startswith('Paste '):
                    key = event[6:].lower().replace(' ', '_').replace('/', '_').replace("message2", "encrypted_decrypted")##insane bug
                    pasted_text = paste_from_clipboard()
                    window[key].update(pasted_text)
                    sg.popup('Pasted from clipboard!', title='Success', auto_close=True, auto_close_duration=2)

                if values['private_key'] and event == 'private_key':## not working I don't think
                    private_key = values['private_key'].strip()
                    public_key = derive_public_key_from_private_key(private_key)
                    if public_key:
                        window['public_address'].update(public_key)
                    else:
                        window['public_address'].update('')

            except Exception as e:
                print(e)
    window.close()

if __name__ == '__main__':
    # try:
    #     private_key, public_key = load_keys_from_file()
    # except FileNotFoundError:
    #     private_key, public_key = generate_key_pair()
    #     save_keys_to_file(private_key, public_key)

    # print('Your Public Address:')
    # print(public_key)
    main()