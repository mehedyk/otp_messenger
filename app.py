# app.py
# Compact OTP Messenger (Tkinter)
import os,base64,tkinter as tk
from tkinter import ttk, filedialog, messagebox

def gen_key(n): return os.urandom(n)
def b64(x): return base64.b64encode(x).decode()
def ub64(s): return base64.b64decode(s.encode())

def encrypt_bytes(pt_bytes,key_bytes):
    return bytes([pt_bytes[i]^key_bytes[i] for i in range(len(pt_bytes))])

def encrypt_text(plaintext):
    pt=plaintext.encode('utf-8')
    key=gen_key(len(pt))
    ct=encrypt_bytes(pt,key)
    return b64(ct), b64(key)

def decrypt_text(ct_b64,key_b64):
    ct=ub64(ct_b64); key=ub64(key_b64)
    if len(ct)!=len(key): raise ValueError("Key length mismatch")
    pt=encrypt_bytes(ct,key)
    return pt.decode('utf-8',errors='replace')

# --- GUI ---
root=tk.Tk(); root.title("OTP Messenger (Local)")
root.geometry("820x520")
frm=ttk.Frame(root,padding=12); frm.pack(fill='both',expand=True)

# Input
ttk.Label(frm,text="Plaintext / Sender").grid(row=0,column=0,sticky='w')
txt_in=tk.Text(frm,height=6,width=80); txt_in.grid(row=1,column=0,columnspan=4,pady=6)

# Buttons: Generate/Encrypt
def on_generate():
    pt=txt_in.get('1.0','end').rstrip('\n')
    if not pt: messagebox.showinfo("Info","Type a message first"); return
    ct_b64,key_b64=encrypt_text(pt)
    ent_cipher.delete('1.0','end'); ent_cipher.insert('1.0',ct_b64)
    ent_key.delete('1.0','end'); ent_key.insert('1.0',key_b64)
def on_encrypt(): on_generate()

btn_gen=ttk.Button(frm,text="Generate OTP & Encrypt",command=on_generate); btn_gen.grid(row=2,column=0,sticky='w',pady=6)

# Cipher and Key display
ttk.Label(frm,text="Ciphertext (base64)").grid(row=3,column=0,sticky='w')
ent_cipher=tk.Text(frm,height=6,width=80); ent_cipher.grid(row=4,column=0,columnspan=4,pady=6)
ttk.Label(frm,text="OTP Key (base64)").grid(row=5,column=0,sticky='w')
ent_key=tk.Text(frm,height=4,width=80); ent_key.grid(row=6,column=0,columnspan=4,pady=6)

# Decrypt
def on_decrypt():
    ct=ent_cipher.get('1.0','end').strip()
    key=ent_key.get('1.0','end').strip()
    if not ct or not key: messagebox.showinfo("Info","Ciphertext and key required"); return
    try:
        pt=decrypt_text(ct,key)
    except Exception as e:
        messagebox.showerror("Error",f"Decryption failed: {e}"); return
    txt_out.delete('1.0','end'); txt_out.insert('1.0',pt)

btn_dec=ttk.Button(frm,text="Decrypt",command=on_decrypt); btn_dec.grid(row=7,column=0,sticky='w',pady=6)

# Output
ttk.Label(frm,text="Decrypted / Receiver").grid(row=8,column=0,sticky='w')
txt_out=tk.Text(frm,height=5,width=80); txt_out.grid(row=9,column=0,columnspan=4,pady=6)

# Utilities: Save/Load/Copy
def save_to_file(text,kind):
    fn=filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("Text","*.txt"),("All","*.*")],title=f"Save {kind}")
    if fn:
        with open(fn,'w',encoding='utf-8') as f: f.write(text)
def load_from_file(target):
    fn=filedialog.askopenfilename(title="Load file",filetypes=[("Text","*.txt"),("All","*.*")])
    if fn:
        with open(fn,'r',encoding='utf-8') as f:
            target.delete('1.0','end'); target.insert('1.0',f.read())

ttk.Button(frm,text="Save Cipher",command=lambda: save_to_file(ent_cipher.get('1.0','end').strip(),"cipher")).grid(row=10,column=0,sticky='w')
ttk.Button(frm,text="Save Key",command=lambda: save_to_file(ent_key.get('1.0','end').strip(),"key")).grid(row=10,column=1,sticky='w')
ttk.Button(frm,text="Load Cipher",command=lambda: load_from_file(ent_cipher)).grid(row=10,column=2,sticky='w')
ttk.Button(frm,text="Load Key",command=lambda: load_from_file(ent_key)).grid(row=10,column=3,sticky='w')

def copy_to_clipboard(widget):
    s=widget.get('1.0','end').strip()
    root.clipboard_clear(); root.clipboard_append(s)
ttk.Button(frm,text="Copy Cipher",command=lambda: copy_to_clipboard(ent_cipher)).grid(row=11,column=0,sticky='w')
ttk.Button(frm,text="Copy Key",command=lambda: copy_to_clipboard(ent_key)).grid(row=11,column=1,sticky='w')
ttk.Button(frm,text="Copy Plaintext",command=lambda: copy_to_clipboard(txt_in)).grid(row=11,column=2,sticky='w')

# small help
help_txt="OTP rules: key must be random, same length as message, used only once. This demo stores key locally (not secure for real world)."
ttk.Label(frm,text=help_txt,wraplength=760).grid(row=12,column=0,columnspan=4,pady=8)

root.mainloop()