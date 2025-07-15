import tkinter as tk
from tkinter import filedialog, messagebox
import re
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import os
from datetime import datetime
import requests
import ipaddress
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from dotenv import load_dotenv
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Log Analyzer")
        self.root.geometry("600x400")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.apache_path = ""
        self.ssh_path = ""

        self.set_dark_mode()
        self.build_ui()

    def on_close(self):
        try:
            plt.close('all')
        except:
            pass
        self.root.destroy()

    def set_dark_mode(self):
        self.root.configure(bg="#1e1e1e")
        self.default_fg = "#ffffff"
        self.accent_fg = "#00d9ff"
        self.button_bg = "#3a3a3a"
        self.entry_bg = "#2a2a2a"

    def styled_label(self, parent, text, size=10, bold=False):
        font_style = ("Arial", size, "bold" if bold else "normal")
        return tk.Label(parent, text=text, font=font_style, fg=self.default_fg, bg="#1e1e1e")

    def build_ui(self):
        header = self.styled_label(self.root, "Log File Analyzer", size=16, bold=True)
        header.pack(pady=10)

        self.styled_label(self.root, "Select Apache Log File:").pack()
        self.apache_label = self.styled_label(self.root, "No file selected", size=9)
        self.apache_label.pack()
        tk.Button(self.root, text="Browse Apache Log", command=self.browse_apache, bg=self.button_bg, fg=self.default_fg).pack(pady=5)

        self.styled_label(self.root, "Select SSH Log File:").pack(pady=(10, 0))
        self.ssh_label = self.styled_label(self.root, "No file selected", size=9)
        self.ssh_label.pack()
        tk.Button(self.root, text="Browse SSH Log", command=self.browse_ssh, bg=self.button_bg, fg=self.default_fg).pack(pady=5)

        tk.Button(self.root, text="Run Analysis", command=self.run_analysis, bg="green", fg="white", width=20).pack(pady=15)
        tk.Button(self.root, text="View Report", command=self.open_report, width=20, bg=self.button_bg, fg=self.default_fg).pack()
        tk.Button(self.root, text="Export as PDF", command=self.export_report_to_pdf, width=20, bg=self.button_bg, fg=self.default_fg).pack(pady=(10, 0))

        self.status_label = self.styled_label(self.root, "", size=10)
        self.status_label.pack(pady=10)

    def browse_apache(self):
        path = filedialog.askopenfilename(filetypes=[("Log files", "*.log *.txt")])
        if path:
            self.apache_path = path
            self.apache_label.config(text=path, fg=self.accent_fg)

    def browse_ssh(self):
        path = filedialog.askopenfilename(filetypes=[("Log files", "*.log *.txt")])
        if path:
            self.ssh_path = path
            self.ssh_label.config(text=path, fg=self.accent_fg)

    def run_analysis(self):
        if not self.apache_path and not self.ssh_path:
            messagebox.showerror("Error", "Please select at least one log file.")
            return

        self.status_label.config(text="Analyzing logs...")

        apache_data = self.analyze_apache(self.apache_path) if self.apache_path else None
        ssh_data = self.analyze_ssh(self.ssh_path) if self.ssh_path else None

        self.generate_report(apache_data, ssh_data)
        self.status_label.config(text="Analysis complete. Report saved.")
        messagebox.showinfo("Done", "Check 'report.txt', 'apache_traffic.png', and 'ssh_failed_attempts.png'.")

    def analyze_apache(self, path):
        ip_counter = Counter()
        suspicious_ips = defaultdict(int)
        pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(GET|POST) .*?" (\d{3})'

        with open(path, 'r') as f:
            for line in f:
                match = re.match(pattern, line)
                if match:
                    ip, _, status = match.groups()
                    ip_counter[ip] += 1
                    if status.startswith("4") or status.startswith("5"):
                        suspicious_ips[ip] += 1

        if ip_counter:
            top_ips = ip_counter.most_common(5)
            ips, counts = zip(*top_ips)
            plt.bar(ips, counts, color="skyblue")
            plt.title("Top Apache IPs by Requests")
            plt.xlabel("IP Address")
            plt.ylabel("Request Count")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig("apache_traffic.png")
            plt.close()

        return suspicious_ips

    def analyze_ssh(self, path):
        failed_counter = Counter()
        invalid_counter = Counter()
        pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*(Failed|Accepted|Invalid).*from (\d+\.\d+\.\d+\.\d+)'

        with open(path, 'r') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    _, action, ip = match.groups()
                    if action == "Failed":
                        failed_counter[ip] += 1
                    elif action == "Invalid":
                        invalid_counter[ip] += 1

        if failed_counter:
            top_failed = failed_counter.most_common(5)
            ips, counts = zip(*top_failed)
            plt.bar(ips, counts, color="orange")
            plt.title("Top SSH Failed Login IPs")
            plt.xlabel("IP Address")
            plt.ylabel("Failed Attempts")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig("ssh_failed_attempts.png")
            plt.close()

        return {
            "failed": failed_counter,
            "invalid": invalid_counter
        }

    def get_geolocation(self, ip):
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
            if response.status_code == 200:
                data = response.json()
                return f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country_name', '')}"
            else:
                return "Location not found"
        except:
            return "Location error"

    def check_abuseipdb(self, ip):
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 30
            }
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()["data"]
                score = data.get("abuseConfidenceScore", 0)
                print(f"[DEBUG] {ip} => Abuse Confidence Score: {score}")
                return score >= 50
            else:
                print(f"[DEBUG] API error {response.status_code} for {ip}")
                return False
        except Exception as e:
            print(f"[DEBUG] AbuseIPDB error for {ip}: {e}")
            return False

    def generate_report(self, apache_data, ssh_data):
        with open("report.txt", "w", encoding="utf-8") as report:
            report.write(f"Log Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            if apache_data:
                report.write("Suspicious Apache IPs (More than 10 errors):\n")
                for ip, count in apache_data.items():
                    if count > 10:
                        location = self.get_geolocation(ip)
                        blacklisted = self.check_abuseipdb(ip)
                        report.write(f"{ip} => {count} suspicious requests ({location}) {'⚠️ Blacklisted' if blacklisted else ''}\n")
                report.write("\n")

            if ssh_data:
                report.write("SSH Failed Login Attempts (5 or more):\n")
                for ip, count in ssh_data['failed'].items():
                    if count >= 5:
                        location = self.get_geolocation(ip)
                        blacklisted = self.check_abuseipdb(ip)
                        report.write(f"{ip} => {count} failed attempts ({location}) {'⚠️ Blacklisted' if blacklisted else ''}\n")

                report.write("\nSSH Invalid User Attempts:\n")
                for ip, count in ssh_data['invalid'].items():
                    location = self.get_geolocation(ip)
                    blacklisted = self.check_abuseipdb(ip)
                    report.write(f"{ip} => {count} invalid user attempts ({location}) {'⚠️ Blacklisted' if blacklisted else ''}\n")

    def export_report_to_pdf(self):
        txt_path = "report.txt"
        pdf_path = "report.pdf"

        if not os.path.exists(txt_path):
            messagebox.showwarning("File Missing", "Text report not found. Run analysis first.")
            return

        try:
            with open(txt_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()

            doc = SimpleDocTemplate(pdf_path, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()
            heading = styles['Heading1']
            subheading = styles['Heading2']
            body = styles['BodyText']

            elements.append(Paragraph("🛡️ Cyber Log Analysis Report", heading))
            elements.append(Spacer(1, 12))
            elements.append(Paragraph(lines[0].strip(), body))
            elements.append(Spacer(1, 12))

            section = None
            data = []
            for line in lines[2:]:
                if line.strip() == "":
                    if data:
                        t = Table(data, repeatRows=1)
                        t.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#404040")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 9),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                            ("BACKGROUND", (0, 1), (-1, -1), colors.lightgrey),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ]))
                        elements.append(t)
                        elements.append(Spacer(1, 16))
                        data = []
                    continue

                if line.startswith("Suspicious Apache IPs"):
                    section = "Apache"
                    elements.append(Paragraph("🛑 Suspicious Apache IPs", subheading))
                    data = [["IP Address", "Count", "Location", "Status"]]
                elif line.startswith("SSH Failed Login Attempts"):
                    section = "FailedSSH"
                    elements.append(Paragraph("🔐 SSH Failed Login Attempts", subheading))
                    data = [["IP Address", "Count", "Location", "Status"]]
                elif line.startswith("SSH Invalid User Attempts"):
                    section = "InvalidSSH"
                    elements.append(Paragraph("🚫 SSH Invalid User Attempts", subheading))
                    data = [["IP Address", "Count", "Location", "Status"]]
                elif "=>" in line:
                    parts = re.split(r" => | \(|\) ", line.strip())
                    ip = parts[0]
                    count = parts[1].split()[0]
                    location = parts[2] if len(parts) > 2 else "-"
                    status = "⚠️ Blacklisted" if "Blacklisted" in line else "Clean"
                    row = [ip, count, location, status]
                    data.append(row)

            if data:
                t = Table(data, repeatRows=1)
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#404040")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(t)

            doc.build(elements)
            messagebox.showinfo("PDF Exported", f"Report saved as {pdf_path}")
            os.system(f"start {pdf_path}" if os.name == 'nt' else f"open {pdf_path}")

        except Exception as e:
            messagebox.showerror("PDF Export Error", f"Error exporting PDF: {e}")

    def open_report(self):
        if os.path.exists("report.txt"):
            os.system("notepad report.txt")
        else:
            messagebox.showwarning("File Missing", "Report not found. Run analysis first.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()
