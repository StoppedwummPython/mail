import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from mail_client_logic import MailClientLogic

# --- CONFIGURATION ---
SERVER_URL = "http://localhost:3000"
REFRESH_INTERVAL_MS = 5000

class App(tk.Tk):
    """The main application class, which acts as the root window and controller."""
    def __init__(self):
        super().__init__()
        self.title("Secure Mail Client")
        self.geometry("400x200")

        self.client_logic = None
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)
        self.show_frame(LoginFrame)

    def show_frame(self, FrameClass):
        """Destroys the current frame and displays a new one."""
        if hasattr(self, 'current_frame'):
            self.current_frame.destroy()
        self.current_frame = FrameClass(parent=self.container, controller=self)
        self.current_frame.pack(fill="both", expand=True)

    def on_login_success(self, client_logic):
        """Transitions from the login page to the main app."""
        self.client_logic = client_logic
        self.geometry("900x700")
        self.minsize(700, 500)
        self.title(f"Secure Inbox - {self.client_logic.address}")
        self.show_frame(MainFrame)

class LoginFrame(ttk.Frame):
    """The Login page UI, built as a Frame."""
    def __init__(self, parent, controller):
        super().__init__(parent, padding=20)
        self.controller = controller
        self.grid_columnconfigure(0, weight=1)
        ttk.Label(self, text="Your Address:", font=('Helvetica', 10, 'bold')).grid(row=0, column=0, sticky="w", pady=5)
        self.address_entry = ttk.Entry(self, width=40)
        self.address_entry.grid(row=1, column=0, sticky="ew")
        self.address_entry.insert(0, "alice@public.com")
        self.address_entry.focus_set()
        self.login_button = ttk.Button(self, text="Login / Register", command=self.handle_login)
        self.login_button.grid(row=2, column=0, sticky="ew", pady=10)
        self.status_label = ttk.Label(self, text="", foreground="red")
        self.status_label.grid(row=3, column=0, sticky="w")

    def handle_login(self):
        address = self.address_entry.get().strip()
        if not address:
            self.status_label.config(text="Address cannot be empty.")
            return
        self.login_button.config(state="disabled")
        self.status_label.config(text="Logging in...", foreground="black")
        threading.Thread(target=self._login_task, args=(address,), daemon=True).start()

    def _login_task(self, address):
        client_logic = MailClientLogic(SERVER_URL, address, lambda msg, color=None: None)
        success, message = client_logic.load_or_register()
        if success:
            self.master.after(0, lambda: self.controller.on_login_success(client_logic))
        else:
            self.master.after(0, self._login_fail, message)

    def _login_fail(self, message):
        self.status_label.config(text=message, foreground="red")
        self.login_button.config(state="normal")

class MainFrame(ttk.Frame):
    """The main application UI (inbox/viewer), built as a Frame."""
    def __init__(self, parent, controller):
        super().__init__(parent, padding=10)
        self.controller = controller
        self.client_logic = controller.client_logic
        self.mail_data = {}
        self.auto_refresh_job = None
        self.controller.protocol("WM_DELETE_WINDOW", self.on_close)

        action_bar = ttk.Frame(self)
        action_bar.pack(fill="x", pady=(0, 10))
        self.compose_button = ttk.Button(action_bar, text="Compose New Mail", command=self.open_compose_window)
        self.compose_button.pack(side="left")

        # --- NEW LOGIC ---
        # If logged in as a domain, disable the compose button as it's a "server" account.
        if self.client_logic.address.startswith('*@'):
            self.compose_button.config(state="disabled")
        # --- END NEW LOGIC ---

        self.status_label = ttk.Label(action_bar, text="Fetching mail...")
        self.status_label.pack(side="right")
        main_pane = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main_pane.pack(fill="both", expand=True)
        list_frame = ttk.Frame(main_pane)
        self._create_mail_list_widgets(list_frame)
        main_pane.add(list_frame, weight=1)
        viewer_frame = ttk.Frame(main_pane, padding=(0, 10, 0, 0))
        self._create_mail_viewer_widgets(viewer_frame)
        main_pane.add(viewer_frame, weight=1)
        self.schedule_mail_check()

    def _create_mail_list_widgets(self, frame):
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        columns = ("from", "to", "timestamp")
        self.mail_list = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        self.mail_list.grid(row=0, column=0, sticky="nsew")
        self.mail_list.heading("from", text="From"); self.mail_list.heading("to", text="To"); self.mail_list.heading("timestamp", text="Timestamp")
        self.mail_list.column("from", width=200); self.mail_list.column("to", width=200); self.mail_list.column("timestamp", width=200)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.mail_list.yview)
        self.mail_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.mail_list.bind("<<TreeviewSelect>>", self.on_mail_select)

    def _create_mail_viewer_widgets(self, frame):
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="From:", font=('Helvetica', 10, 'bold')).grid(row=0, column=0, sticky="w", padx=5)
        self.from_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.from_var).grid(row=0, column=1, sticky="w")
        ttk.Label(frame, text="To:", font=('Helvetica', 10, 'bold')).grid(row=1, column=0, sticky="w", padx=5)
        self.to_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.to_var).grid(row=1, column=1, sticky="w")
        ttk.Label(frame, text="Date:", font=('Helvetica', 10, 'bold')).grid(row=2, column=0, sticky="w", padx=5)
        self.date_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.date_var).grid(row=2, column=1, sticky="w")
        ttk.Separator(frame, orient="horizontal").grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)
        self.mail_body = scrolledtext.ScrolledText(frame, state="disabled", wrap="word", height=8)
        self.mail_body.grid(row=4, column=0, columnspan=2, sticky="nsew")
        frame.rowconfigure(4, weight=1)

    def schedule_mail_check(self):
        threading.Thread(target=self._check_mail_task, daemon=True).start()
        self.auto_refresh_job = self.after(REFRESH_INTERVAL_MS, self.schedule_mail_check)

    def _check_mail_task(self):
        messages, result = self.client_logic.check_inbox()
        if messages is not None:
            self.after(0, self._update_mail_list_gui, messages)
            self.after(0, self.status_label.config, {'text': f"Last updated: {time.strftime('%H:%M:%S')}"})
        else:
            self.after(0, self.status_label.config, {'text': f"Update failed: {result}"})
    
    def _update_mail_list_gui(self, messages):
        selected_id = self.mail_list.selection()[0] if self.mail_list.selection() else None
        self.mail_list.delete(*self.mail_list.get_children())
        self.mail_data.clear()
        for i, msg in enumerate(reversed(messages)):
            item_id = f"mail_{i}"
            self.mail_data[item_id] = msg
            self.mail_list.insert("", tk.END, iid=item_id, values=(msg['from'], msg['to'], msg['timestamp']))
        if selected_id and self.mail_list.exists(selected_id):
            self.mail_list.selection_set(selected_id); self.mail_list.focus(selected_id)

    def on_mail_select(self, event):
        selected_id = self.mail_list.selection()[0] if self.mail_list.selection() else None
        if not selected_id: return
        mail = self.mail_data.get(selected_id)
        if mail:
            self.from_var.set(mail['from']); self.to_var.set(mail['to']); self.date_var.set(mail['timestamp'])
            self.mail_body.config(state="normal")
            self.mail_body.delete("1.0", tk.END); self.mail_body.insert("1.0", mail['content'])
            self.mail_body.config(state="disabled")

    def open_compose_window(self):
        SendMailWindow(self.controller, self.client_logic)

    def on_close(self):
        if self.auto_refresh_job: self.after_cancel(self.auto_refresh_job)
        self.controller.destroy()

class SendMailWindow(tk.Toplevel):
    def __init__(self, master, client_logic):
        super().__init__(master)
        self.title("Compose New Mail"); self.geometry("500x400")
        self.client_logic = client_logic
        frame = ttk.Frame(self, padding=15); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Recipient Address:").pack(fill="x")
        self.recipient_entry = ttk.Entry(frame); self.recipient_entry.pack(fill="x", pady=(0, 10))
        ttk.Label(frame, text="Message:").pack(fill="x")
        self.message_text = scrolledtext.ScrolledText(frame, wrap="word"); self.message_text.pack(fill="both", expand=True, pady=(0, 10))
        button_frame = ttk.Frame(frame); button_frame.pack(fill="x")
        self.send_button = ttk.Button(button_frame, text="Send", command=self.handle_send); self.send_button.pack(side="right")
        self.status_label = ttk.Label(button_frame, text=""); self.status_label.pack(side="left")
        self.transient(master); self.grab_set(); self.focus_set()

    def handle_send(self):
        recipient = self.recipient_entry.get().strip()
        message = self.message_text.get("1.0", tk.END).strip()
        if not recipient or not message:
            self.status_label.config(text="Recipient and message required.", foreground="red"); return
        self.send_button.config(state="disabled"); self.status_label.config(text="Sending...", foreground="black")
        threading.Thread(target=self._send_task, args=(recipient, message), daemon=True).start()

    def _send_task(self, recipient, message):
        success, result_message = self.client_logic.send_mail(recipient, message)
        if success:
            self.after(0, self.status_label.config, {'text': 'Mail Sent!', 'foreground': 'green'})
            self.after(1000, self.destroy)
        else:
            self.after(0, self.status_label.config, {'text': result_message, 'foreground': 'red'})
            self.after(0, self.send_button.config, {'state': 'normal'})

if __name__ == "__main__":
    app = App()
    app.mainloop()