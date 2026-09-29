"""
SENTRA GUI Launcher

This GUI uses the current SENTRA network architecture:

    GUI
      ↓
    IdentityManager
      ↓
    SentraClient
      ↓
    mTLS + Ed25519 authentication
      ↓
    X25519 + HKDF-SHA256 + AES-256-GCM
      ↓
    SentraServer

Run:
    python scripts/generate_dev_certs.py --clients SENDER RECEIVER
    python main.py

The GUI does NOT implement its own RSA encryption or raw socket protocol.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import scrolledtext, messagebox, font, simpledialog

from identity.manager import IdentityManager
from network.client import SentraClient
from network.server import SentraServer


# ============================================================
# CONFIGURATION
# ============================================================

THEME = {
    "bg": "#0d1117",
    "fg": "#00ffff",
    "success": "#00ff00",
    "error": "#ff0000",
    "accent": "#00ffff",
    "panel": "#111111",
    "input": "#222222",
}

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432

BASE = Path(__file__).resolve().parent
CERTS = BASE / "certs"
DATA = BASE / "data"


# ============================================================
# SENTRA APPLICATION
# ============================================================

class SecureMessagingApp(tk.Toplevel):
    """
    GUI terminal backed by the real SENTRA SentraClient.

    All network communication and encryption is handled by the
    existing SENTRA network/security modules.
    """

    def __init__(
        self,
        master,
        username: str,
        recipient_name: str,
        passphrase: str,
    ):
        super().__init__(master)

        self.username_input = username.strip()
        self.recipient_name = recipient_name.strip()

        self.server_host = SERVER_HOST
        self.server_port = SERVER_PORT

        self.title(
            f"SENTRA Secure Terminal - {self.username_input}"
        )
        self.geometry("900x650")
        self.configure(bg=THEME["bg"])
        self.minsize(800, 600)

        self.client: SentraClient | None = None
        self.identity: IdentityManager | None = None

        self.setup_ui()

        try:
            self.identity = IdentityManager.load_or_create(
                self.username_input,
                passphrase,
                data_root=str(DATA),
            )

            self.username = self.identity.username

            self.update_identity_display()

            self.start_client()

        except Exception as exc:
            messagebox.showerror(
                "Identity / Connection Error",
                f"Could not initialize SENTRA identity:\n\n{exc}",
                parent=self,
            )
            self.destroy()
            return

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ========================================================
    # UI
    # ========================================================

    def setup_ui(self):
        header_font = font.Font(
            family="Courier",
            size=16,
            weight="bold",
        )

        text_font = font.Font(
            family="Courier",
            size=10,
        )

        header = tk.Label(
            self,
            text=":: SECURE TRANSMISSION CHANNEL ::",
            bg=THEME["bg"],
            fg=THEME["accent"],
            font=header_font,
        )
        header.pack(pady=10)

        main_frame = tk.Frame(
            self,
            bg=THEME["bg"],
        )
        main_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=20,
            pady=10,
        )

        self.chat_display = scrolledtext.ScrolledText(
            main_frame,
            state="disabled",
            bg="#000000",
            fg=THEME["success"],
            font=text_font,
            height=20,
        )
        self.chat_display.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
        )

        sidebar = tk.Frame(
            main_frame,
            bg=THEME["panel"],
            width=230,
        )
        sidebar.pack(
            side=tk.RIGHT,
            fill=tk.Y,
            padx=(10, 0),
        )
        sidebar.pack_propagate(False)

        tk.Label(
            sidebar,
            text="-- SYSTEM STATUS --",
            bg=THEME["panel"],
            fg=THEME["accent"],
            font=header_font,
        ).pack(pady=10)

        self.info_label = tk.Label(
            sidebar,
            text="",
            bg=THEME["panel"],
            fg="#cccccc",
            justify=tk.LEFT,
            font=text_font,
        )
        self.info_label.pack(
            padx=10,
            anchor="w",
        )

        input_frame = tk.Frame(
            self,
            bg=THEME["bg"],
        )
        input_frame.pack(
            fill=tk.X,
            padx=20,
            pady=10,
        )

        self.msg_entry = tk.Entry(
            input_frame,
            bg=THEME["input"],
            fg="white",
            insertbackground="white",
            font=text_font,
        )
        self.msg_entry.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
            padx=(0, 10),
        )

        self.msg_entry.bind(
            "<Return>",
            lambda event: self.send_message(),
        )

        btn = tk.Button(
            input_frame,
            text="<TRANSMIT>",
            bg=THEME["accent"],
            fg="black",
            font=header_font,
            command=self.send_message,
            relief=tk.FLAT,
        )
        btn.pack(side=tk.RIGHT)

        self.status_var = tk.StringVar(
            value="INITIALIZING..."
        )

        tk.Label(
            self,
            textvariable=self.status_var,
            bg=THEME["bg"],
            fg=THEME["accent"],
            font=("Courier", 10),
        ).pack(
            pady=(0, 10)
        )

    def update_identity_display(self):
        username = (
            self.identity.username
            if self.identity
            else self.username_input
        )

        info_text = (
            f"\n"
            f"AGENT ID: {username}\n"
            f"TARGET ID: {self.recipient_name}\n"
            f"\n"
            f"NODE: {self.server_host}:{self.server_port}\n"
            f"CONNECTION: [INITIALIZING]\n"
            f"PROTOCOL: mTLS + Ed25519\n"
            f"E2EE: X25519 + HKDF + AES-256-GCM\n"
        )

        self.info_label.config(
            text=info_text
        )

    # ========================================================
    # LOGGING
    # ========================================================

    def log_message(self, message: str):
        """
        Safely update Tkinter from the GUI thread.
        """

        def update():
            try:
                self.chat_display.config(
                    state="normal"
                )

                timestamp = time.strftime(
                    "%H:%M:%S"
                )

                self.chat_display.insert(
                    tk.END,
                    f"[{timestamp}] {message}\n",
                )

                self.chat_display.see(
                    tk.END
                )

                self.chat_display.config(
                    state="disabled"
                )

            except tk.TclError:
                pass

        try:
            self.after(0, update)
        except tk.TclError:
            pass

    def set_status(
        self,
        message: str,
        color=None,
    ):
        def update():
            try:
                self.status_var.set(message)

            except tk.TclError:
                pass

        try:
            self.after(0, update)
        except tk.TclError:
            pass

    # ========================================================
    # SENTRA CLIENT CALLBACKS
    # ========================================================

    def on_client_message(
        self,
        sender: str,
        plaintext: str,
    ):
        """
        Called by SentraClient after:

            envelope verification
            ↓
            AES-GCM decryption
            ↓
            plaintext recovered
        """

        self.log_message(
            f"RX: {plaintext}"
        )

    def on_client_event(
        self,
        message: str,
    ):
        self.log_message(
            f"-- {message}"
        )

        if "Connected and authenticated" in message:
            self.set_status(
                "CONNECTED + AUTHENTICATED",
                THEME["success"],
            )

            self.update_connection_display(
                "CONNECTED"
            )

        elif "Connection lost" in message:
            self.set_status(
                "CONNECTION LOST - RECONNECTING...",
                THEME["error"],
            )

            self.update_connection_display(
                "RECONNECTING"
            )

    def update_connection_display(
        self,
        state: str,
    ):
        def update():
            try:
                username = (
                    self.identity.username
                    if self.identity
                    else self.username_input
                )

                info_text = (
                    f"\n"
                    f"AGENT ID: {username}\n"
                    f"TARGET ID: {self.recipient_name}\n"
                    f"\n"
                    f"NODE: {self.server_host}:{self.server_port}\n"
                    f"CONNECTION: [{state}]\n"
                    f"PROTOCOL: mTLS + Ed25519\n"
                    f"E2EE: X25519 + HKDF + AES-256-GCM\n"
                )

                self.info_label.config(
                    text=info_text
                )

            except tk.TclError:
                pass

        try:
            self.after(0, update)
        except tk.TclError:
            pass

    # ========================================================
    # CLIENT STARTUP
    # ========================================================

    def start_client(self):
        if self.identity is None:
            raise RuntimeError(
                "Identity was not initialized"
            )

        certificate_username = {
            "RECEIVER": "bob",
            "SENDER": "alice",
        }.get(self.identity.username.upper(), self.identity.username)

        if not (
            (CERTS / f"client_{certificate_username}.crt").is_file()
            and (CERTS / f"client_{certificate_username}.key").is_file()
        ):
            certificate_username = self.identity.username

        certfile = (
            CERTS
            / f"client_{certificate_username}.crt"
        )

        keyfile = (
            CERTS
            / f"client_{certificate_username}.key"
        )

        cafile = CERTS / "ca.crt"

        missing = [
            str(path)
            for path in (
                certfile,
                keyfile,
                cafile,
            )
            if not path.exists()
        ]

        if missing:
            raise FileNotFoundError(
                "Required SENTRA certificate files are missing:\n\n"
                + "\n".join(missing)
                + "\n\n"
                "Generate development certificates first."
            )

        self.client = SentraClient(
            host=self.server_host,
            port=self.server_port,
            certfile=str(certfile),
            keyfile=str(keyfile),
            cafile=str(cafile),
            identity=self.identity,
            on_message=self.on_client_message,
            on_event=self.on_client_event,
        )

        self.log_message(
            "--- Starting SENTRA secure client... ---"
        )

        self.update_connection_display(
            "CONNECTING"
        )

        self.client_thread = threading.Thread(
            target=self.client.run_forever,
            daemon=True,
        )

        self.client_thread.start()

    # ========================================================
    # SEND MESSAGE
    # ========================================================

    def send_message(self):
        msg = self.msg_entry.get().strip()

        if not msg:
            return

        if self.client is None:
            self.log_message(
                "--- Client is not initialized. ---"
            )
            return

        try:
            if not self.client.wait_until_connected(
                timeout=0.1
            ):
                self.log_message(
                    "--- Client is not connected yet. Please wait. ---"
                )
                return

            message_id = self.client.send_message(
                self.recipient_name,
                msg,
            )

            self.log_message(
                f"TX: {msg}"
            )

            self.log_message(
                f"-- Encrypted message sent: {message_id}"
            )

            self.msg_entry.delete(
                0,
                tk.END,
            )

        except Exception as exc:
            self.log_message(
                f"--- Transmission Error: {exc} ---"
            )

    # ========================================================
    # CLOSE
    # ========================================================

    def on_closing(self):
        try:
            if self.client is not None:
                self.client.stop()
        except Exception:
            pass

        self.destroy()


# ============================================================
# MAIN LAUNCHER
# ============================================================

class AppLauncher(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title(
            "SENTRA Launcher"
        )

        self.geometry(
            "600x500"
        )

        self.configure(
            bg=THEME["bg"]
        )

        self.server: SentraServer | None = None
        self.server_thread: threading.Thread | None = None

        tk.Label(
            self,
            text="SENTRA INITIATOR",
            bg=THEME["bg"],
            fg=THEME["accent"],
            font=("Courier", 24, "bold"),
        ).pack(
            pady=20
        )

        status_frame = tk.Frame(
            self,
            bg=THEME["bg"],
            highlightbackground="#ff00ff",
            highlightthickness=2,
        )
        status_frame.pack(
            fill=tk.X,
            padx=40,
            pady=10,
        )

        self.status_label = tk.Label(
            status_frame,
            text="Server Offline",
            bg=THEME["bg"],
            fg=THEME["error"],
            font=("Courier", 12),
        )

        self.status_label.pack(
            side=tk.LEFT,
            padx=10,
            pady=10,
        )

        self.server_button = tk.Button(
            status_frame,
            text="ONLINE",
            bg=THEME["accent"],
            fg="black",
            font=("Courier", 10, "bold"),
            command=self.start_server,
        )

        self.server_button.pack(
            side=tk.RIGHT,
            padx=10,
            pady=5,
        )

        form_frame = tk.Frame(
            self,
            bg=THEME["bg"],
            highlightbackground="#ff00ff",
            highlightthickness=2,
        )

        form_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=40,
            pady=20,
        )

        tk.Label(
            form_frame,
            text=":: DEPLOY AGENT TERMINAL ::",
            bg=THEME["bg"],
            fg=THEME["accent"],
            font=("Courier", 14),
        ).pack(
            pady=15
        )

        input_grid = tk.Frame(
            form_frame,
            bg=THEME["bg"],
        )

        input_grid.pack(
            pady=10
        )

        tk.Label(
            input_grid,
            text="AGENT ID:",
            bg=THEME["bg"],
            fg="white",
            font=("Courier", 12),
        ).grid(
            row=0,
            column=0,
            sticky="w",
            pady=5,
        )

        self.agent_id_entry = tk.Entry(
            input_grid,
            bg="#333",
            fg="white",
            insertbackground="white",
            font=("Courier", 12),
        )

        self.agent_id_entry.insert(
            0,
            "RECEIVER",
        )

        self.agent_id_entry.grid(
            row=0,
            column=1,
            pady=5,
            padx=10,
        )

        tk.Label(
            input_grid,
            text="TARGET ID:",
            bg=THEME["bg"],
            fg="white",
            font=("Courier", 12),
        ).grid(
            row=1,
            column=0,
            sticky="w",
            pady=5,
        )

        self.target_id_entry = tk.Entry(
            input_grid,
            bg="#333",
            fg="white",
            insertbackground="white",
            font=("Courier", 12),
        )

        self.target_id_entry.insert(
            0,
            "SENDER",
        )

        self.target_id_entry.grid(
            row=1,
            column=1,
            pady=5,
            padx=10,
        )

        tk.Button(
            form_frame,
            text="<LAUNCH>",
            bg=THEME["accent"],
            fg="black",
            font=("Courier", 14, "bold"),
            command=self.launch_terminal,
        ).pack(
            fill=tk.X,
            padx=40,
            pady=30,
        )

        self.protocol(
            "WM_DELETE_WINDOW",
            self.on_closing,
        )

    # ========================================================
    # SERVER
    # ========================================================

    def start_server(self):
        if self.server_thread and self.server_thread.is_alive():
            self.status_label.config(
                text="Server already ONLINE",
                fg=THEME["success"],
            )
            return

        try:
            DATA.mkdir(
                parents=True,
                exist_ok=True,
            )

            required_files = [
                CERTS / "server.crt",
                CERTS / "server.key",
                CERTS / "ca.crt",
            ]

            missing = [
                str(path)
                for path in required_files
                if not path.exists()
            ]

            if missing:
                messagebox.showerror(
                    "Certificates Missing",
                    "Generate SENTRA development certificates first:\n\n"
                    "python scripts/generate_dev_certs.py "
                    "--clients SENDER RECEIVER\n\n"
                    "Missing:\n"
                    + "\n".join(missing),
                    parent=self,
                )
                return

            self.server = SentraServer(
                host=SERVER_HOST,
                port=SERVER_PORT,
                certfile=str(
                    CERTS / "server.crt"
                ),
                keyfile=str(
                    CERTS / "server.key"
                ),
                cafile=str(
                    CERTS / "ca.crt"
                ),
                registry_db=str(
                    DATA / "registry.db"
                ),
                offline_db=str(
                    DATA / "offline_queue.db"
                ),
            )

            self.server_thread = threading.Thread(
                target=self.run_server,
                daemon=True,
            )

            self.server_thread.start()

            self.status_label.config(
                text=f"Server ONLINE @ {SERVER_HOST}:{SERVER_PORT}",
                fg=THEME["success"],
            )

            self.server_button.config(
                state=tk.DISABLED,
                text="ONLINE",
            )

        except Exception as exc:
            messagebox.showerror(
                "Server Error",
                f"Could not start SENTRA server:\n\n{exc}",
                parent=self,
            )

    def run_server(self):
        try:
            self.server.start()
        except Exception as exc:
            self.after(
                0,
                lambda: self.status_label.config(
                    text=f"Server Error: {exc}",
                    fg=THEME["error"],
                ),
            )

    # ========================================================
    # LAUNCH CLIENT
    # ========================================================

    def launch_terminal(self):
        agent_id = (
            self.agent_id_entry
            .get()
            .strip()
        )

        target_id = (
            self.target_id_entry
            .get()
            .strip()
        )

        if not agent_id or not target_id:
            messagebox.showerror(
                "Error",
                "Agent ID and Target ID are required.",
                parent=self,
            )
            return

        if agent_id.lower() == target_id.lower():
            messagebox.showerror(
                "Error",
                "Agent ID and Target ID must be different.",
                parent=self,
            )
            return

        if not self.server_thread or not self.server_thread.is_alive():
            messagebox.showwarning(
                "Server Offline",
                "Click ONLINE first to start the SENTRA server.",
                parent=self,
            )
            return

        passphrase = simpledialog.askstring(
            "Identity Vault",
            f"Enter the vault passphrase for '{agent_id}':",
            show="*",
            parent=self,
        )

        if passphrase is None:
            return

        if not passphrase:
            messagebox.showerror(
                "Invalid Passphrase",
                "A non-empty vault passphrase is required.",
                parent=self,
            )
            return

        SecureMessagingApp(
            self,
            agent_id,
            target_id,
            passphrase,
        )

    # ========================================================
    # CLOSE
    # ========================================================

    def on_closing(self):
        try:
            if self.server is not None:
                self.server.stop()
        except Exception:
            pass

        self.destroy()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    app = AppLauncher()
    app.mainloop()