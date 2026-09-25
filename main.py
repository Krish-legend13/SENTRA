import os
import sys
import socket
import threading
import json
import base64
import tkinter as tk
from tkinter import scrolledtext, messagebox, font
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import datetime
import ctypes

# --- Configuration / Theme ---
THEME = {
    "bg": "#0d1117",       # Dark background
    "fg": "#00ffff",       # Cyan text
    "success": "#00ff00",  # Green
    "error": "#ff0000",    # Red
    "accent": "#00ffff"
}

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

# --- Admin Check ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# --- Crypto Helper Functions ---
def generate_keys(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return
    print(f"Generating new RSA key pair for {os.path.dirname(public_key_path)}...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(private_key_path, "wb") as f:
        f.write(pem_private)
    with open(public_key_path, "wb") as f:
        f.write(pem_public)

def load_private_key(path="private_key.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def get_public_key_bytes(path="public_key.pem"):
    with open(path, "rb") as f:
        return f.read()

def encrypt_message(message, public_key):
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

# --- Server Logic ---
server_clients = {}
server_lock = threading.Lock()

def handle_client(client_socket):
    username = None
    try:
        handshake_data = client_socket.recv(4096).decode('utf-8')
        if not handshake_data: return
        
        data = json.loads(handshake_data)
        username = data.get("username")
        public_key_b64 = data.get("public_key")
        
        with server_lock:
            server_clients[client_socket] = {
                "username": username.upper(),
                "public_key": public_key_b64
            }
            
        print(f"Connection accepted: {username}")
        
        while True:
            message = client_socket.recv(4096).decode('utf-8')
            if not message: break
            
            packet = json.loads(message)
            
            # Handle Key Request
            if packet.get("type") == "KEY_REQUEST":
                target_username = packet.get("target", "").upper()
                with server_lock:
                    target_client = next(
                        (cs for cs, info in server_clients.items() if info["username"] == target_username), 
                        None
                    )
                    if target_client:
                        target_key = server_clients[target_client]["public_key"]
                        response = {
                            "type": "KEY_RESPONSE",
                            "target": target_username,
                            "public_key": target_key
                        }
                        client_socket.send(json.dumps(response).encode('utf-8'))
                    else:
                        client_socket.send(json.dumps({"type": "KEY_RESPONSE", "target": target_username}).encode('utf-8'))
            
            # Handle normal encrypted messages
            elif packet.get("type") == "MESSAGE":
                target_username = packet.get("target", "").upper()
                with server_lock:
                    recipient_socket = next(
                        (cs for cs, info in server_clients.items() if info["username"] == target_username), 
                        None
                    )
                    if recipient_socket:
                        recipient_socket.send(message.encode('utf-8'))
                        print(f"Routed message from {username} to {target_username}")

    except Exception as e:
        print(f"Client handling error: {e}")
    finally:
        with server_lock:
            if client_socket in server_clients:
                del server_clients[client_socket]
        client_socket.close()
        print(f"Client disconnected: {username}")

def start_server_logic(status_callback):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen()
        status_callback(f"Server ONLINE @ {SERVER_HOST}:{SERVER_PORT}", THEME["success"])
        
        while True:
            client_socket, _ = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
            
    except Exception as e:
        status_callback(f"Server Error: {e}", THEME["error"])
    finally:
        server_socket.close()

# --- Secure Messaging Client ---
class SecureMessagingApp(tk.Toplevel):
    def __init__(self, master, username, recipient_name):
        super().__init__(master)
        self.username = username.upper()
        self.recipient_name = recipient_name.upper()
        
        self.title(f"SENTRA Secure Terminal - {self.username}")
        self.geometry("900x650")
        self.configure(bg=THEME["bg"])
        self.minsize(800, 600)
        
        self.SERVER_HOST = '127.0.0.1'
        self.SERVER_PORT = 65432
        
        self.user_data_dir = f"data_{self.username}"
        os.makedirs(self.user_data_dir, exist_ok=True)
        
        self.PRIVATE_KEY_FILE = os.path.join(self.user_data_dir, "private_key.pem")
        self.PUBLIC_KEY_FILE = os.path.join(self.user_data_dir, "public_key.pem")
        
        self.client_socket = None
        self.recipient_public_key = None
        
        self.load_client_keys()
        self.setup_ui()
        self.connect_to_server()
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def load_client_keys(self):
        generate_keys(self.PRIVATE_KEY_FILE, self.PUBLIC_KEY_FILE)
        try:
            self.private_key = load_private_key(self.PRIVATE_KEY_FILE)
            self.public_key_b64 = base64.b64encode(
                get_public_key_bytes(self.PUBLIC_KEY_FILE)
            ).decode('utf-8')
        except Exception:
            messagebox.showerror("Fatal Error", f"Could not load key files for {self.username}.")
            self.destroy()

    def setup_ui(self):
        header_font = font.Font(family="Courier", size=16, weight="bold")
        text_font = font.Font(family="Courier", size=10)
        
        header = tk.Label(self, text=":: SECURE TRANSMISSION CHANNEL ::", bg=THEME["bg"], fg=THEME["accent"], font=header_font)
        header.pack(pady=10)
        
        main_frame = tk.Frame(self, bg=THEME["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.chat_display = scrolledtext.ScrolledText(main_frame, state='disabled', bg="#000000", fg=THEME["success"], font=text_font, height=20)
        self.chat_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        sidebar = tk.Frame(main_frame, bg="#111111", width=200)
        sidebar.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        sidebar.pack_propagate(False)
        
        tk.Label(sidebar, text="-- SYSTEM STATUS --", bg="#111111", fg=THEME["accent"], font=header_font).pack(pady=10)
        info_text = f"\nAGENT ID: {self.username}\nTARGET ID: {self.recipient_name}\n\nNODE: {self.SERVER_HOST}:{self.SERVER_PORT}\nCONNECTION: [CONNECTED]\nPROTOCOL: RSA-2048/OAEP-SHA256\nE2EE: [ACTIVE]\n"
        tk.Label(sidebar, text=info_text, bg="#111111", fg="#cccccc", justify=tk.LEFT, font=text_font).pack(padx=10, anchor="w")
        
        input_frame = tk.Frame(self, bg=THEME["bg"])
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.msg_entry = tk.Entry(input_frame, bg="#222222", fg="white", font=text_font)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        
        btn = tk.Button(input_frame, text="<TRANSMIT>", bg=THEME["accent"], fg="black", font=header_font, command=self.send_message, relief=tk.FLAT)
        btn.pack(side=tk.RIGHT)

    def log_message(self, message):
        self.chat_display.config(state='normal')
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] {message}\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.SERVER_HOST, self.SERVER_PORT))
            
            handshake = {
                "username": self.username,
                "public_key": self.public_key_b64
            }
            self.client_socket.send(json.dumps(handshake).encode('utf-8'))
            self.log_message("--- Connected to Server. Requesting Target Key... ---")
            
            self.request_target_key()
            
            # Start listening thread
            self.listener_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.listener_thread.start()
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            self.destroy()

    def request_target_key(self):
        req = {
            "type": "KEY_REQUEST",
            "target": self.recipient_name
        }
        self.client_socket.send(json.dumps(req).encode('utf-8'))

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(4096).decode('utf-8')
                if not message: 
                    self.log_message("--- Connection lost to server. ---")
                    break
                
                data = json.loads(message)
                
                if data.get("type") == "KEY_RESPONSE":
                    if data.get("public_key"):
                        self.recipient_public_key = serialization.load_pem_public_key(
                            base64.b64decode(data["public_key"])
                        )
                        self.log_message(f"--- Target key acquired. Ready to transmit. ---")
                    else:
                        self.log_message(f"--- Target {self.recipient_name} is offline. Waiting... ---")
                
                elif data.get("type") == "MESSAGE":
                    try:
                        encrypted_payload = base64.b64decode(data.get("payload"))
                        decrypted_msg = decrypt_message(encrypted_payload, self.private_key)
                        self.log_message(f"RX: {decrypted_msg}")
                    except Exception as decrypt_error:
                        self.log_message(f"--- Error decrypting incoming message. (Key mismatch) ---")
                    
            except Exception as e:
                print(f"Receive error: {e}")
                self.log_message("--- Connection error in listener. ---")
                break

    def send_message(self):
        msg = self.msg_entry.get().strip()
        if not msg:
            return
            
        if not self.recipient_public_key:
            self.request_target_key()
            self.log_message(f"--- Requesting key for {self.recipient_name} again... ---")
            return

        try:
            encrypted_payload = encrypt_message(msg, self.recipient_public_key)
            payload_b64 = base64.b64encode(encrypted_payload).decode('utf-8')
            
            packet = {
                "type": "MESSAGE",
                "sender": self.username,
                "target": self.recipient_name,
                "payload": payload_b64,
                "timestamp": str(datetime.datetime.now())
            }
            
            self.client_socket.send(json.dumps(packet).encode('utf-8'))
            self.log_message(f"TX: {msg}")
            self.msg_entry.delete(0, tk.END)
            
        except Exception as e:
            self.log_message(f"--- Transmission Error: {e} ---")

    def on_closing(self):
        if self.client_socket:
            self.client_socket.close()
        self.destroy()

# --- Main Launcher UI ---
class AppLauncher(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SENTRA Launcher")
        self.geometry("600x500")
        self.configure(bg=THEME["bg"])
        
        tk.Label(self, text="SENTRA INITIATOR", bg=THEME["bg"], fg=THEME["accent"], font=("Courier", 24, "bold")).pack(pady=20)
        
        status_frame = tk.Frame(self, bg=THEME["bg"], highlightbackground="#ff00ff", highlightthickness=2)
        status_frame.pack(fill=tk.X, padx=40, pady=10)
        
        self.status_label = tk.Label(status_frame, text="Server Offline", bg=THEME["bg"], fg=THEME["error"], font=("Courier", 12))
        self.status_label.pack(side=tk.LEFT, padx=10, pady=10)
        
        tk.Button(status_frame, text="ONLINE", bg=THEME["accent"], fg="black", font=("Courier", 10, "bold"), command=self.start_server).pack(side=tk.RIGHT, padx=10, pady=5)
        
        form_frame = tk.Frame(self, bg=THEME["bg"], highlightbackground="#ff00ff", highlightthickness=2)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        tk.Label(form_frame, text=":: DEPLOY AGENT TERMINAL ::", bg=THEME["bg"], fg=THEME["accent"], font=("Courier", 14)).pack(pady=15)
        
        input_grid = tk.Frame(form_frame, bg=THEME["bg"])
        input_grid.pack(pady=10)
        
        tk.Label(input_grid, text="AGENT ID:", bg=THEME["bg"], fg="white", font=("Courier", 12)).grid(row=0, column=0, sticky="w", pady=5)
        self.agent_id_entry = tk.Entry(input_grid, bg="#333", fg="white", font=("Courier", 12))
        self.agent_id_entry.insert(0, "RECEIVER")
        self.agent_id_entry.grid(row=0, column=1, pady=5, padx=10)
        
        tk.Label(input_grid, text="TARGET ID:", bg=THEME["bg"], fg="white", font=("Courier", 12)).grid(row=1, column=0, sticky="w", pady=5)
        self.target_id_entry = tk.Entry(input_grid, bg="#333", fg="white", font=("Courier", 12))
        self.target_id_entry.insert(0, "SENDER")
        self.target_id_entry.grid(row=1, column=1, pady=5, padx=10)
        
        tk.Button(form_frame, text="<LAUNCH>", bg=THEME["accent"], fg="black", font=("Courier", 14, "bold"), command=self.launch_terminal).pack(fill=tk.X, padx=40, pady=30)

    def start_server(self):
        def update_status(msg, color):
            self.status_label.config(text=msg, fg=color)
        threading.Thread(target=start_server_logic, args=(update_status,), daemon=True).start()

    def launch_terminal(self):
        agent_id = self.agent_id_entry.get().strip()
        target_id = self.target_id_entry.get().strip()
        
        if not agent_id or not target_id:
            messagebox.showerror("Error", "Agent ID and Target ID required.")
            return
            
        os.makedirs(f"data_{target_id}", exist_ok=True)
        generate_keys(f"data_{target_id}/private_key.pem", f"data_{target_id}/public_key.pem")
            
        SecureMessagingApp(self, agent_id, target_id)

if __name__ == "__main__":
    if sys.platform == "win32" and not is_admin():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Administrator Privileges Required", "This application requires administrator privileges to bind to a network port.\n\nPlease right-click the script and select 'Run as administrator'.")
        sys.exit(1)

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
    except ImportError:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Dependency Missing", "The 'cryptography' library is required.\nPlease install it using: pip install cryptography")
        sys.exit(1)

    app = AppLauncher()
    app.mainloop()