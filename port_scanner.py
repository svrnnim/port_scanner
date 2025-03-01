import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import mysql.connector
import nmap
import threading
import re

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.root.geometry("600x400")
        self.root.resizable(False, False)
        self.root.configure(bg="#ADD8E6")

        # Input Frame
        input_frame = ttk.Frame(root, padding=10, style="InputFrame.TFrame")
        input_frame.pack(fill=tk.X)

        ttk.Label(input_frame, text="Enter Target IP:", font=("Arial", 12, "bold"), background="#ADD8E6", foreground="black").pack(side=tk.LEFT, padx=5)

        self.target_ip_entry = ttk.Entry(input_frame, width=35, font=("Arial", 12))
        self.target_ip_entry.pack(side=tk.LEFT, padx=5)

        self.start_button = ttk.Button(input_frame, text="Start", command=self.start_scan, style="StartButton.TButton")
        self.start_button.pack(side=tk.LEFT, padx=5, ipadx=2)

        # Result Frame
        result_frame = ttk.Frame(root, padding=10, style="ResultFrame.TFrame")
        result_frame.pack(fill=tk.BOTH, expand=True)

        self.result_text = scrolledtext.ScrolledText(result_frame, height=15, width=70, state=tk.DISABLED, font=("Courier", 10), bg="#E0FFFF", fg="#00008B")
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Styling
        self.style = ttk.Style()
        self.style.configure("InputFrame.TFrame", background="#ADD8E6")
        self.style.configure("ResultFrame.TFrame", background="#ADD8E6")
        self.style.configure("StartButton.TButton", background="#1E90FF", foreground="black", font=("Arial", 10, "bold"), padding=5)
        self.style.map("StartButton.TButton", background=[("active", "#4682B4")])

    def start_scan(self):
        target_ip = self.target_ip_entry.get().strip()
        if not self.validate_ip(target_ip):
            messagebox.showerror("Error", "Please enter a valid IP address.")
            return

        self.start_button.config(state=tk.DISABLED)  # Disable button while scanning
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, f"Scanning {target_ip} ...\n")
        self.result_text.config(state=tk.DISABLED)

        # Start scanning in a separate thread
        threading.Thread(target=self.scan_ports, args=(target_ip,), daemon=True).start()

    def scan_ports(self, target_ip):
        scanner = nmap.PortScanner()
        try:
            scanner.scan(target_ip, '1-1024')  # Scan ports 1-1024

            host_state = scanner[target_ip].state()

            # Get open ports
            open_ports = [port for proto in scanner[target_ip].all_protocols() for port in scanner[target_ip][proto] if scanner[target_ip][proto][port]['state'] == 'open']

            # Display results
            result = f"Host: {target_ip}\nState: {host_state}\nOpen Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}\n\n"
            self.root.after(0, self.update_results, result)  # Schedule GUI update in the main thread

            # Save results to database and file
            self.save_to_database(target_ip, open_ports)
            self.save_to_file(target_ip, open_ports)
        except Exception as e:
            self.root.after(0, self.update_results, f"Error scanning {target_ip}: {str(e)}\n", True)  # Schedule GUI update in the main thread
        finally:
            self.root.after(0, self.enable_start_button)  # Schedule GUI update in the main thread

    def update_results(self, message, error=False):
        self.result_text.config(state=tk.NORMAL)
        if error:
            self.result_text.insert(tk.END, message, "error")
        else:
            self.result_text.insert(tk.END, message, "success")
        self.result_text.config(state=tk.DISABLED)

    def enable_start_button(self):
        self.start_button.config(state=tk.NORMAL)  # Re-enable the button

    @staticmethod
    def save_to_database(ip, open_ports):
        try:
            # Connect to the MySQL database
            connection = mysql.connector.connect(
                host="localhost",
                user="root",
                password="xybp56mr",
                database="port_scanner_db"
            )
            cursor = connection.cursor()

            # Insert each open port as a separate row
            for port in open_ports:
                query = "INSERT INTO scans (ip_address, port, status) VALUES (%s, %s, %s)"
                cursor.execute(query, (ip, port, "open"))  # Insert IP, port, and status

            # Commit the transaction
            connection.commit()
            print(f"Data inserted: IP={ip}, Open Ports={open_ports}")  # Debugging
        except mysql.connector.Error as e:
            print(f"Database Error: {e}")
        finally:
            # Close the database connection
            if connection.is_connected():
                cursor.close()
                connection.close()

    @staticmethod
    def save_to_file(ip, open_ports, filename="scan_results.txt"):
        try:
            with open(filename, "a") as file:
                file.write(f"Scan Result for {ip}:\n")
                file.write(f"Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}\n")
                file.write("-" * 40 + "\n")
        except Exception as e:
            print(f"Error saving to file: {e}")

    @staticmethod
    def validate_ip(ip):
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return bool(pattern.match(ip))

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()