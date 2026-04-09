import tkinter as tk
from tkinter import messagebox
import subprocess

def run_scan():
    url = entry.get()

    if not url:
        messagebox.showerror("Error", "Please enter a target URL")
        return

    try:
        cmd = f"python vxscan.py --url {url} --max-pages 20 --depth 2"
        subprocess.Popen(cmd, shell=True)
        messagebox.showinfo("Success", "Scan started! Check terminal for progress.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


root = tk.Tk()
root.title("VXScan GUI Dashboard")
root.geometry("400x200")

tk.Label(root, text="Enter Target URL", font=("Arial", 12)).pack(pady=10)

entry = tk.Entry(root, width=40)
entry.pack()

tk.Button(root, text="Start Scan", command=run_scan).pack(pady=20)

root.mainloop()