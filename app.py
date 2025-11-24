#!/usr/bin/env python3
"""
SecureComm: One-Time Pad (OTP) Cipher Messaging System
Educational implementation with GUI - Unbreakable encryption
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import base64
from datetime import datetime
import json

class OneTimePadCipher:
    """One-Time Pad cipher implementation - theoretically unbreakable"""
    
    def __init__(self):
        self.key = None
        self.key_hex = None
    
    def generate_key(self, length):
        """Generate random OTP key"""
        self.key = os.urandom(length)
        self.key_hex = self.key.hex()
        return self.key_hex
    
    def encrypt(self, plaintext):
        """Encrypt using OTP - XOR each byte with key"""
        pt_bytes = plaintext.encode('utf-8')
        
        # Generate key if not exists or if too short
        if not self.key or len(self.key) < len(pt_bytes):
            self.generate_key(len(pt_bytes))
        
        # XOR operation
        ciphertext = bytes([pt_bytes[i] ^ self.key[i] for i in range(len(pt_bytes))])
        
        # Return base64 encoded ciphertext and key
        ct_b64 = base64.b64encode(ciphertext).decode()
        key_b64 = base64.b64encode(self.key[:len(pt_bytes)]).decode()
        
        return ct_b64, key_b64
    
    def decrypt(self, ciphertext_b64, key_b64):
        """Decrypt using OTP - XOR ciphertext with key"""
        try:
            ct_bytes = base64.b64decode(ciphertext_b64.encode())
            key_bytes = base64.b64decode(key_b64.encode())
            
            if len(ct_bytes) != len(key_bytes):
                raise ValueError("⚠ Key length mismatch! Decryption impossible.")
            
            # XOR operation
            plaintext_bytes = bytes([ct_bytes[i] ^ key_bytes[i] for i in range(len(ct_bytes))])
            plaintext = plaintext_bytes.decode('utf-8', errors='replace')
            
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption error: {e}")
    
    def validate_key(self, key_b64, plaintext_length):
        """Validate if key is sufficient for plaintext"""
        try:
            key_bytes = base64.b64decode(key_b64.encode())
            if len(key_bytes) < plaintext_length:
                return False, f"Key too short: {len(key_bytes)} bytes, need {plaintext_length}"
            return True, "Valid"
        except:
            return False, "Invalid key format"


class SecureCommApp:
    """Main OTP messaging application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SecureComm - One-Time Pad Messenger")
        self.root.geometry("1100x800")
        self.root.configure(bg="#0a0e27")
        
        self.cipher = OneTimePadCipher()
        self.current_key = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup UI with terminalistic theme"""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background="#0a0e27", foreground="#00ff41")
        style.configure('TFrame', background="#0a0e27")
        style.configure('TButton', background="#1a1f3a", foreground="#00ff41")
        style.map('TButton', background=[('active', '#2d3561')])
        style.configure('Title.TLabel', font=("Courier", 14, "bold"))
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        header = ttk.Label(main_frame, text="█ SECURECOMM - ONE-TIME PAD CIPHER SYSTEM █", 
                          style='Title.TLabel')
        header.pack(pady=10)
        
        info = ttk.Label(main_frame, text="[Theoretically Unbreakable Encryption - Proven by Claude Shannon]")
        info.pack(pady=2)
        
        # ============ KEY MANAGEMENT SECTION ============
        key_frame = ttk.LabelFrame(main_frame, text="🔑 Key Management", padding=10)
        key_frame.pack(fill='x', pady=5)
        
        btn_subframe = ttk.Frame(key_frame)
        btn_subframe.pack(fill='x', pady=5)
        
        def gen_new_key():
            """Generate new random key"""
            try:
                key_hex = self.cipher.generate_key(256)
                self.current_key = base64.b64encode(self.cipher.key).decode()
                self.key_display.config(state='normal')
                self.key_display.delete('1.0', 'end')
                self.key_display.insert('1.0', self.current_key)
                self.key_display.config(state='disabled')
                self.status_var.set("✓ New 256-byte random key generated")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        def copy_key():
            """Copy key to clipboard"""
            if self.current_key:
                self.root.clipboard_clear()
                self.root.clipboard_append(self.current_key)
                messagebox.showinfo("Success", "Key copied to clipboard")
            else:
                messagebox.showwarning("Warning", "Generate a key first")
        
        ttk.Button(btn_subframe, text="🎲 Generate New Key (256 bytes)", command=gen_new_key).pack(side='left', padx=5)
        ttk.Button(btn_subframe, text="📋 Copy Key", command=copy_key).pack(side='left', padx=5)
        
        ttk.Label(key_frame, text="Current Key (Base64):").pack(anchor='w', pady=(5, 0))
        self.key_display = tk.Text(key_frame, height=4, width=120, bg="#1a1f3a", 
                                    fg="#00ff41", font=("Courier", 9), state='disabled')
        self.key_display.pack(fill='x', padx=5, pady=5)
        
        # ============ ENCRYPTION SECTION ============
        input_frame = ttk.LabelFrame(main_frame, text="📝 Plaintext Message (Sender)", padding=10)
        input_frame.pack(fill='both', expand=True, pady=5)
        
        self.input_text = tk.Text(input_frame, height=6, width=120, bg="#1a1f3a", 
                                   fg="#00ff41", font=("Courier", 10), insertbackground="#00ff41")
        self.input_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Encrypt button
        encrypt_frame = ttk.Frame(main_frame)
        encrypt_frame.pack(fill='x', pady=5)
        
        def encrypt_msg():
            plaintext = self.input_text.get('1.0', 'end').strip()
            if not plaintext:
                messagebox.showwarning("Warning", "Enter message to encrypt")
                return
            
            try:
                ct_b64, key_b64 = self.cipher.encrypt(plaintext)
                self.current_key = key_b64
                
                self.output_text.config(state='normal')
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', ct_b64)
                self.output_text.config(state='normal')
                
                self.key_display.config(state='normal')
                self.key_display.delete('1.0', 'end')
                self.key_display.insert('1.0', key_b64)
                self.key_display.config(state='disabled')
                
                msg_len = len(plaintext.encode('utf-8'))
                self.status_var.set(f"✓ Encrypted | Message: {msg_len} bytes | Key: {len(key_b64)} chars (Base64)")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        
        ttk.Button(encrypt_frame, text="🔒 Encrypt Message", command=encrypt_msg).pack(side='left', padx=5)
        
        # ============ CIPHERTEXT SECTION ============
        output_frame = ttk.LabelFrame(main_frame, text="🔐 Ciphertext Message (Encrypted)", padding=10)
        output_frame.pack(fill='both', expand=True, pady=5)
        
        self.output_text = tk.Text(output_frame, height=6, width=120, bg="#1a1f3a", 
                                    fg="#ff0000", font=("Courier", 10), insertbackground="#00ff41")
        self.output_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # ============ DECRYPTION SECTION ============
        decrypt_frame = ttk.Frame(main_frame)
        decrypt_frame.pack(fill='x', pady=5)
        
        def decrypt_msg():
            ciphertext = self.output_text.get('1.0', 'end').strip()
            key = self.key_display.get('1.0', 'end').strip()
            
            if not ciphertext or not key:
                messagebox.showwarning("Warning", "Ciphertext and Key required")
                return
            
            try:
                plaintext = self.cipher.decrypt(ciphertext, key)
                self.input_text.delete('1.0', 'end')
                self.input_text.insert('1.0', plaintext)
                self.status_var.set(f"✓ Decrypted | Message recovered: {len(plaintext)} chars")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        def clear_all():
            self.input_text.delete('1.0', 'end')
            self.output_text.delete('1.0', 'end')
            self.status_var.set("Cleared")
        
        ttk.Button(decrypt_frame, text="🔓 Decrypt Message", command=decrypt_msg).pack(side='left', padx=5)
        ttk.Button(decrypt_frame, text="🗑 Clear All", command=clear_all).pack(side='left', padx=5)
        
        # ============ FILE OPERATIONS ============
        file_frame = ttk.LabelFrame(main_frame, text="💾 File Operations", padding=10)
        file_frame.pack(fill='x', pady=5)
        
        def save_msg():
            plaintext = self.input_text.get('1.0', 'end').strip()
            ciphertext = self.output_text.get('1.0', 'end').strip()
            key = self.key_display.get('1.0', 'end').strip()
            
            if not plaintext and not ciphertext:
                messagebox.showwarning("Warning", "Nothing to save")
                return
            
            filename = filedialog.asksaveasfilename(defaultextension=".json", 
                                                   filetypes=[("JSON", "*.json"), ("Text", "*.txt")])
            if filename:
                try:
                    data = {
                        "timestamp": datetime.now().isoformat(),
                        "algorithm": "One-Time Pad (OTP)",
                        "plaintext": plaintext,
                        "ciphertext": ciphertext,
                        "key": key,
                        "key_length": len(key),
                        "message_bytes": len(plaintext.encode('utf-8')) if plaintext else 0
                    }
                    with open(filename, 'w') as f:
                        json.dump(data, f, indent=2)
                    messagebox.showinfo("Success", "Message saved with key")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        
        def load_msg():
            filename = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("Text", "*.txt")])
            if filename:
                try:
                    with open(filename, 'r') as f:
                        if filename.endswith('.json'):
                            data = json.load(f)
                            self.input_text.delete('1.0', 'end')
                            self.input_text.insert('1.0', data.get("plaintext", ""))
                            self.output_text.delete('1.0', 'end')
                            self.output_text.insert('1.0', data.get("ciphertext", ""))
                            self.key_display.config(state='normal')
                            self.key_display.delete('1.0', 'end')
                            self.key_display.insert('1.0', data.get("key", ""))
                            self.key_display.config(state='disabled')
                            self.current_key = data.get("key", "")
                        else:
                            content = f.read()
                            self.output_text.delete('1.0', 'end')
                            self.output_text.insert('1.0', content)
                    messagebox.showinfo("Success", "Message loaded")
                except Exception as e:
                    messagebox.showerror("Error", f"Load failed: {e}")
        
        def copy_cipher():
            ciphertext = self.output_text.get('1.0', 'end').strip()
            if ciphertext:
                self.root.clipboard_clear()
                self.root.clipboard_append(ciphertext)
                messagebox.showinfo("Success", "Ciphertext copied to clipboard")
        
        ttk.Button(file_frame, text="💾 Save Message + Key", command=save_msg).pack(side='left', padx=5)
        ttk.Button(file_frame, text="📂 Load Message", command=load_msg).pack(side='left', padx=5)
        ttk.Button(file_frame, text="📋 Copy Ciphertext", command=copy_cipher).pack(side='left', padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready | Generate a key to start")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief='sunken', 
                              foreground="#00ff41", background="#0a0e27")
        status_bar.pack(fill='x', pady=5)
        
        # Info panel
        info_frame = ttk.LabelFrame(main_frame, text="ℹ️  Algorithm Info", padding=10)
        info_frame.pack(fill='x', pady=5)
        
        info_text = """ONE-TIME PAD (OTP): Perfect encryption proven by Shannon (1949)
• Each bit of plaintext is XORed with a random key bit
• Key must be: random, same length as message, used only ONCE
• Ciphertext provides no information about plaintext without the exact key
• MATHEMATICALLY UNBREAKABLE (if key is truly random and kept secret)"""
        
        ttk.Label(info_frame, text=info_text, justify='left').pack(anchor='w')


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureCommApp(root)
    root.mainloop()