import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import threading
import math
import random
from main import run_scan_logic

# --------------------- Scan Functions ---------------------

def start_scan():
    target = target_entry.get().strip()
    if not target:
        return

    scan_button.config(state="disabled")
    progress_var.set(0)
    progress_label.config(text="SCANNING... 0%")
    output_box.config(state="normal")
    output_box.delete("1.0", tk.END)
    output_box.config(state="disabled")

    start_radar()
    threading.Thread(target=run_scan_thread, args=(target,), daemon=True).start()


def run_scan_thread(target):
    results = run_scan_logic(target, progress_callback=update_progress)
    root.after(0, display_results, target, results)
    root.after(0, lambda: scan_button.config(state="normal"))
    root.after(0, lambda: progress_label.config(text="SCAN COMPLETE"))
    root.after(0, stop_radar)


def update_progress(percent):
    progress_var.set(percent)
    progress_label.config(text=f"SCANNING... {percent}%")
    root.update_idletasks()


def display_results(target, results):
    output_box.config(state="normal")

    output_box.insert(tk.END, f"\n[✓] Scan completed for {target}\n\n", "success")

    for item in results:
        output_box.insert(tk.END, f"Host: {item.get('host')}\n", "header")
        output_box.insert(tk.END, f"Port: {item.get('port')}\n")
        output_box.insert(tk.END, f"Protocol: {item.get('protocol')}\n")
        output_box.insert(tk.END, f"Service: {item.get('service')}\n")
        output_box.insert(tk.END, f"Product: {item.get('product')}\n")
        output_box.insert(tk.END, f"Version: {item.get('version', 'Unknown')}\n")

        vulnerabilities = item.get("vulnerabilities", [])

        if vulnerabilities:
            output_box.insert(tk.END, "\nVulnerabilities Found:\n", "warning")
            output_box.insert(tk.END, "-" * 90 + "\n")

            for vuln in vulnerabilities:
                severity = vuln.get("severity")
                tag = "low"
                if severity == "Critical":
                    tag = "critical"
                elif severity == "High":
                    tag = "high"
                elif severity == "Medium":
                    tag = "medium"

                output_box.insert(tk.END, f"CVE ID: {vuln.get('cve_id')}\n", tag)
                output_box.insert(tk.END, f"CVSS Score: {vuln.get('cvss_score')}\n")
                output_box.insert(tk.END, f"Severity: {severity}\n", tag)
                output_box.insert(tk.END, f"Description: {vuln.get('description')}\n")
                output_box.insert(tk.END, "-" * 90 + "\n")
        else:
            output_box.insert(tk.END, "\nNo known vulnerabilities found.\n", "safe")

        output_box.insert(tk.END, "=" * 100 + "\n\n")

    output_box.config(state="disabled")


# --------------------- Advanced Radar Animation ---------------------

radar_angle = 0
radar_running = False
blips = []

def create_blips():
    global blips
    blips.clear()
    for _ in range(15):
        r = random.randint(10, 80)
        angle = random.randint(0, 360)
        blips.append((r, angle))


def draw_radar():
    global radar_angle

    radar_canvas.delete("all")

    center_x = 100
    center_y = 100
    radius = 90

    # Background circle
    radar_canvas.create_oval(5, 5, 195, 195, fill="#001a00", outline="")

    # Concentric circles
    for r in range(30, 91, 30):
        radar_canvas.create_oval(
            center_x - r, center_y - r,
            center_x + r, center_y + r,
            outline="#00ffcc"
        )

    # Cross lines
    radar_canvas.create_line(center_x, 10, center_x, 190, fill="#00ffcc")
    radar_canvas.create_line(10, center_y, 190, center_y, fill="#00ffcc")

    # Sweep sector
    radar_canvas.create_arc(
        center_x - radius,
        center_y - radius,
        center_x + radius,
        center_y + radius,
        start=radar_angle,
        extent=35,
        fill="#00ff99",
        outline="",
        stipple="gray25"
    )

    # Blips
    for r, angle in blips:
        angle_rad = math.radians(angle)
        x = center_x + r * math.cos(angle_rad)
        y = center_y - r * math.sin(angle_rad)

        radar_canvas.create_oval(
            x-2, y-2,
            x+2, y+2,
            fill="#00ffcc",
            outline=""
        )

    radar_angle = (radar_angle + 3) % 360

    if radar_running:
        root.after(30, draw_radar)


def start_radar():
    global radar_running
    radar_running = True
    create_blips()
    draw_radar()


def stop_radar():
    global radar_running
    radar_running = False


# --------------------- GUI Setup ---------------------

root = tk.Tk()
root.title("Mini Vulnerability Scanner")
root.geometry("1200x800")
root.configure(bg="#0d1117")

# --------------------- Top Layout ---------------------

top_frame = tk.Frame(root, bg="#0d1117")
top_frame.pack(fill="x", pady=10, padx=20)

# Left: Logo
logo_frame = tk.Frame(top_frame, bg="#0d1117")
logo_frame.pack(side=tk.LEFT, padx=10)

try:
    logo_image = Image.open("logo.png")
    logo_image = logo_image.resize((300, 300))
    logo_photo = ImageTk.PhotoImage(logo_image)
    logo_label = tk.Label(logo_frame, image=logo_photo, bg="#0d1117")
    logo_label.pack()
except:
    logo_label = tk.Label(logo_frame, text="[Logo]", bg="#0d1117", fg="#00ffcc")
    logo_label.pack()

# Center: Title + Radar
center_frame = tk.Frame(top_frame, bg="#0d1117")
center_frame.pack(side=tk.LEFT, expand=True)

title_label = tk.Label(
    center_frame,
    text="⚡ # VULNERABILITY SCANNER # ⚡",
    font=("Consolas", 22, "bold"),
    fg="#00ffcc",
    bg="#0d1117"
)
title_label.pack(pady=5)

radar_canvas = tk.Canvas(
    center_frame,
    width=200,
    height=200,
    bg="#0d1117",
    highlightthickness=0
)
radar_canvas.pack(pady=10)

# Right: Target + Button
right_frame = tk.Frame(top_frame, bg="#0d1117")
right_frame.pack(side=tk.RIGHT, padx=10)

tk.Label(
    right_frame,
    text="Target IP:",
    font=("Consolas", 14),
    fg="#00ffcc",
    bg="#0d1117"
).pack(pady=5)

target_entry = tk.Entry(
    right_frame,
    font=("Consolas", 14),
    bg="#161b22",
    fg="#00ffcc",
    insertbackground="#00ffcc",
    width=25
)
target_entry.pack(pady=5)

scan_button = tk.Button(
    right_frame,
    text="Start Scan",
    command=start_scan,
    font=("Consolas", 14, "bold"),
    bg="#238636",
    fg="white",
    activebackground="#2ea043"
)
scan_button.pack(pady=10)

# --------------------- Progress Bar ---------------------

progress_var = tk.IntVar()

progress_bar = ttk.Progressbar(
    root,
    variable=progress_var,
    maximum=100,
    length=1100
)
progress_bar.pack(pady=10)

progress_label = tk.Label(
    root,
    text="IDLE",
    font=("Consolas", 12, "bold"),
    fg="#00ffcc",
    bg="#0d1117"
)
progress_label.pack()

# --------------------- Terminal Output ---------------------

output_box = tk.Text(
    root,
    wrap="word",
    bg="#161b22",
    fg="#c9d1d9",
    font=("Consolas", 10),
    insertbackground="#00ffcc"
)
output_box.pack(fill="both", expand=True, padx=40, pady=20)

scrollbar = tk.Scrollbar(output_box)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
output_box.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=output_box.yview)

output_box.tag_config("header", foreground="#58a6ff")
output_box.tag_config("success", foreground="#3fb950")
output_box.tag_config("warning", foreground="#f0883e")
output_box.tag_config("critical", foreground="#ff4d4d")
output_box.tag_config("high", foreground="#ff7b72")
output_box.tag_config("medium", foreground="#f2cc60")
output_box.tag_config("low", foreground="#8b949e")
output_box.tag_config("safe", foreground="#3fb950")

output_box.config(state="disabled")

root.mainloop()
