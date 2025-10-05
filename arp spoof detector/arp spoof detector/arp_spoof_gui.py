import os
import sys
import time
import logging
import threading
import platform
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from tkinter.font import Font
import netifaces
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# Import the detector functionality
from arp_spoofing_detector import ARPSpoofDetector

# Try importing Scapy's windows utils, handle if Scapy is not fully installed/functional yet
try:
    from scapy.arch.windows import get_windows_if_list
    scapy_if_list = get_windows_if_list()
except ImportError:
    scapy_if_list = []
    print("Warning: Scapy's Windows utilities not found. Interface names might be limited.")
except Exception as e:
    scapy_if_list = []
    print(f"Warning: Error loading Scapy interface list: {e}")

class ARPSpoofDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Spoofing Detector")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)
        
        # Define light and dark color schemes
        self.light_theme = {
            'bg_color': "#FFFFFF",
            'accent_color': "#1DB954",  # Spotify Green
            'highlight_color': "#1ed760",  # Lighter Spotify Green
            'alert_color': "#e63946",
            'success_color': "#1DB954",
            'neutral_color': "#535353",
            'text_color': "#191414",  # Spotify Black
            'light_accent': "#f8f8f8",
            'chart_bg': "#FFFFFF",
            'button_hover': "#1ed760"  # Lighter green for hover
        }
        
        self.dark_theme = {
            'bg_color': "#191414",  # Spotify Black
            'accent_color': "#1DB954",  # Spotify Green
            'highlight_color': "#1ed760",  # Lighter Spotify Green
            'alert_color': "#e63946",
            'success_color': "#1DB954",
            'neutral_color': "#b3b3b3",  # Spotify Gray
            'text_color': "#FFFFFF",
            'light_accent': "#282828",  # Spotify Dark Gray
            'chart_bg': "#282828",
            'button_hover': "#1ed760"  # Lighter green for hover
        }
        
        # Set current theme
        self.is_dark_mode = False
        self.current_theme = self.light_theme
        
        # Set modern theme colors
        self.bg_color = self.current_theme['bg_color']
        self.accent_color = self.current_theme['accent_color']
        self.highlight_color = self.current_theme['highlight_color']
        self.alert_color = self.current_theme['alert_color']
        self.success_color = self.current_theme['success_color']
        self.neutral_color = self.current_theme['neutral_color']
        self.text_color = self.current_theme['text_color']
        self.light_accent = self.current_theme['light_accent']
        
        # Apply theme to root window
        self.root.configure(bg=self.bg_color)
        
        # Configure logging to GUI handler
        self.log_handler = None
        
        # Create detector instance
        self.detector = ARPSpoofDetector()
        
        # Set up variables
        self.is_monitoring = False
        self.is_simulating = False
        self.interface_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.stats_var = tk.StringVar(value="Devices: 0 | Suspicious: 0")
        self.packet_count_var = tk.StringVar(value="Total Packets: 0")
        
        # For limiting alert popups
        self.active_alerts = 0
        self.max_alerts = 1  # Only show one alert at a time
        
        # Store chart data
        self.chart_data = {"timestamps": [], "packet_counts": []}
        
        # Create UI elements
        self.create_ui()
        
        # Setup auto-refresh
        self.root.after(1000, self.update_status)
        
        # Configure system logging to redirect to the log widget
        self.setup_logging()
        
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.is_dark_mode = not self.is_dark_mode
        self.current_theme = self.dark_theme if self.is_dark_mode else self.light_theme
        
        # Update colors
        self.bg_color = self.current_theme['bg_color']
        self.accent_color = self.current_theme['accent_color']
        self.highlight_color = self.current_theme['highlight_color']
        self.alert_color = self.current_theme['alert_color']
        self.success_color = self.current_theme['success_color']
        self.neutral_color = self.current_theme['neutral_color']
        self.text_color = self.current_theme['text_color']
        self.light_accent = self.current_theme['light_accent']
        
        # Update root window
        self.root.configure(bg=self.bg_color)
        
        # Update all styled widgets
        style = ttk.Style()
        
        # Update frame styles
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabelframe', background=self.bg_color)
        style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.text_color)
        
        # Update label styles
        style.configure('TLabel', background=self.bg_color, foreground=self.text_color)
        style.configure('Header.TLabel', background=self.bg_color, foreground=self.text_color)
        style.configure('Subheader.TLabel', background=self.bg_color, foreground=self.text_color)
        style.configure('Status.TLabel', background=self.bg_color, foreground=self.text_color)
        
        # Update button styles
        style.configure('Mode.TButton', background=self.accent_color)
        
        # Update notebook style
        style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.light_accent, foreground=self.text_color)
        
        # Update Treeview colors
        style.configure('Treeview', 
                      background=self.bg_color,
                      fieldbackground=self.bg_color,
                      foreground=self.text_color)
        style.configure('Treeview.Heading', 
                      background=self.accent_color,
                      foreground='white')
        
        # Update log text colors
        self.log_text.configure(
            background=self.light_accent,
            foreground=self.text_color
        )
        
        # Update charts background
        self.time_fig.set_facecolor(self.current_theme['chart_bg'])
        self.time_chart.set_facecolor(self.current_theme['chart_bg'])
        self.fig.set_facecolor(self.current_theme['chart_bg'])
        self.chart.set_facecolor(self.current_theme['chart_bg'])
        
        # Update theme button text
        self.theme_btn.configure(text="🌙 Dark Mode" if not self.is_dark_mode else "☀️ Light Mode")
        
        # Redraw charts
        self.update_chart()
        
    def setup_logging(self):
        """Configure the logging system to output to our log widget"""
        try:
            # Remove existing handlers to avoid duplication
            root_logger = logging.getLogger()
            for handler in root_logger.handlers[:]:
                if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                    root_logger.removeHandler(handler)
                    
            # Create our custom log handler
            self.log_handler = LogWidgetHandler(self.log_text)
            self.log_handler.setLevel(logging.INFO)
            
            # Create formatter
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            self.log_handler.setFormatter(formatter)
            
            # Add the handler to the root logger
            root_logger.addHandler(self.log_handler)
            
            # Keep file handler if it exists
            has_file_handler = any(isinstance(h, logging.FileHandler) for h in root_logger.handlers)
            
            # Also redirect stdout/stderr to the log widget
            sys.stdout = TextRedirector(self.log_text)
            sys.stderr = TextRedirector(self.log_text)
            
            # Log that we've initialized
            logging.info("GUI Logger initialized")
        except Exception as e:
            print(f"Error setting up logging: {e}")
            # Fallback to standard logging
            logging.basicConfig(level=logging.INFO)

    def create_ui(self):
        """Create the UI components"""
        # Create modern styled UI
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles with modern colors and fonts
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabelframe', background=self.bg_color)
        style.configure('TLabelframe.Label', 
                       background=self.bg_color, 
                       foreground=self.text_color, 
                       font=('Segoe UI', 11, 'bold'))
        
        # Button styling with Spotify-inspired design
        style.configure('TButton', 
                      font=('Segoe UI', 10, 'bold'), 
                      background=self.accent_color,
                      foreground='white',
                      padding=(12, 8),
                      relief='flat',
                      borderwidth=0)
        style.map('TButton',
                background=[('active', self.current_theme['button_hover']), 
                          ('pressed', self.current_theme['button_hover'])],
                foreground=[('active', 'white'), ('pressed', 'white')])
        
        # Special button styles with Spotify-like appearance
        style.configure('Action.TButton', 
                      font=('Segoe UI', 10, 'bold'),
                      padding=(14, 8),
                      background=self.accent_color)
        
        style.configure('Monitor.TButton', 
                      background=self.success_color,
                      foreground='white',
                      padding=(14, 8))
        style.map('Monitor.TButton',
                background=[('active', self.current_theme['button_hover']), 
                          ('pressed', self.current_theme['button_hover'])],
                foreground=[('active', 'white'), ('pressed', 'white')])
        
        style.configure('Stop.TButton', 
                      background=self.alert_color,
                      foreground='white',
                      padding=(14, 8))
        style.map('Stop.TButton',
                background=[('active', '#ff4d4d'), ('pressed', '#ff4d4d')],
                foreground=[('active', 'white'), ('pressed', 'white')])
                
        # Theme toggle button style
        style.configure('Theme.TButton', 
                      font=('Segoe UI', 10, 'bold'),
                      background=self.light_accent,
                      foreground=self.text_color,
                      padding=(12, 8),
                      relief='flat',
                      borderwidth=0)
        style.map('Theme.TButton',
                background=[('active', self.accent_color), ('pressed', self.accent_color)],
                foreground=[('active', 'white'), ('pressed', 'white')])

        # Label styling
        style.configure('TLabel', 
                      font=('Segoe UI', 10), 
                      background=self.bg_color,
                      foreground=self.text_color)
        style.configure('Header.TLabel', 
                      font=('Segoe UI', 14, 'bold'), 
                      background=self.bg_color,
                      foreground=self.text_color)
        style.configure('Subheader.TLabel', 
                      font=('Segoe UI', 12), 
                      background=self.bg_color,
                      foreground=self.text_color)
        style.configure('Alert.TLabel', 
                      foreground=self.alert_color, 
                      font=('Segoe UI', 10, 'bold'), 
                      background=self.bg_color)
        style.configure('Status.TLabel', 
                      foreground=self.neutral_color, 
                      font=('Segoe UI', 9), 
                      background=self.bg_color)
        
        # Tree view styling
        style.configure('Treeview', 
                      font=('Segoe UI', 9),
                      background=self.bg_color,
                      fieldbackground=self.bg_color)
        style.configure('Treeview.Heading', 
                      font=('Segoe UI', 10, 'bold'),
                      background=self.accent_color,
                      foreground='white')
        style.map('Treeview', 
                background=[('selected', self.accent_color)],
                foreground=[('selected', 'white')])
        
        # Special button styles
        style.configure('Action.TButton', 
                      font=('Segoe UI', 10, 'bold'),
                      padding=(14, 8),
                      background=self.accent_color)
        style.configure('Monitor.TButton', 
                      background=self.success_color,
                      foreground='white',
                      padding=(14, 8))
        style.map('Monitor.TButton',
                background=[('active', self.current_theme['button_hover']), 
                          ('pressed', self.current_theme['button_hover'])],
                foreground=[('active', 'white'), ('pressed', 'white')])
        style.configure('Stop.TButton', 
                      background=self.alert_color,
                      foreground='white',
                      padding=(14, 8))
        style.map('Stop.TButton',
                background=[('active', '#ff4d4d'), ('pressed', '#ff4d4d')],
                foreground=[('active', 'white'), ('pressed', 'white')])
        
        # Theme toggle button with custom style
        style.configure('Theme.TButton', 
                      font=('Segoe UI', 10, 'bold'),
                      background=self.light_accent,
                      foreground=self.text_color,
                      padding=(12, 8),
                      relief='flat',
                      borderwidth=0)
        style.map('Theme.TButton',
                background=[('active', self.accent_color), ('pressed', self.accent_color)],
                foreground=[('active', 'white'), ('pressed', 'white')])

        # Main frame with improved spacing and borders
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # App title and header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(header_frame, text="ARP Spoofing Detector", style='Header.TLabel').pack(side=tk.LEFT)
       # ttk.Label(header_frame, text="Protect your network from address spoofing attacks", 
        #        style='Status.TLabel').pack(side=tk.LEFT, padx=(10, 0), pady=2)
        
        # Top control panel with enhanced appearance
        control_frame = ttk.LabelFrame(main_frame, text="Network Controls", padding=15)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Interface selection with improved layout
        interface_frame = ttk.Frame(control_frame)
        interface_frame.pack(fill=tk.X, expand=True, pady=(0, 5))
        
        ttk.Label(interface_frame, text="Network Interface:", 
                style='Subheader.TLabel').pack(side=tk.LEFT, padx=(0, 10))
        
        # Get available interfaces
        interfaces = self.get_available_interfaces()
        interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var, 
                                      values=interfaces, width=40, 
                                      font=('Segoe UI', 10))
        interface_combo.pack(side=tk.LEFT, padx=(0, 15), fill=tk.X, expand=True)
        interface_combo.bind("<<ComboboxSelected>>", self.scan_network)

        # Set default interface
        default_iface = self.detector.get_default_interface()
        if default_iface and default_iface in interfaces:
            self.interface_var.set(default_iface)
        elif interfaces:
            self.interface_var.set(interfaces[0])
            
        # Control buttons with improved styling
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, expand=True, pady=5)
        
        self.scan_btn = ttk.Button(button_frame, text="🔍 Scan Network", 
                                 command=self.scan_network, style='Action.TButton')
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.monitor_btn = ttk.Button(button_frame, text="▶ Start Monitoring", 
                                    command=self.toggle_monitoring, style='Action.TButton')
        self.monitor_btn.pack(side=tk.LEFT, padx=8)

        self.simulate_btn = ttk.Button(button_frame, text="⚠ Simulate Attack", 
                                     command=self.show_simulation_dialog, style='Action.TButton')
        self.simulate_btn.pack(side=tk.LEFT, padx=8) 

        self.export_btn = ttk.Button(button_frame, text="💾 Export Data", 
                           command=self.export_data, style='Action.TButton')
        self.export_btn.pack(side=tk.LEFT, padx=8)
        
        # Theme toggle button with custom style
        style.configure('Theme.TButton', 
                      font=('Segoe UI', 10, 'bold'),
                      background=self.light_accent,
                      foreground=self.text_color,
                      padding=(12, 8),
                      relief='flat',
                      borderwidth=0)
        style.map('Theme.TButton',
                background=[('active', self.accent_color), ('pressed', self.accent_color)],
                foreground=[('active', 'white'), ('pressed', 'white')])

        # Theme toggle button
        self.theme_btn = ttk.Button(button_frame, text="🌙 Dark Mode", 
                                  command=self.toggle_theme, style='Theme.TButton')
        self.theme_btn.pack(side=tk.RIGHT, padx=8)
        
        # Enhanced status bar with visual indicators
        status_frame = ttk.Frame(main_frame, padding=(5, 8))
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Add a border to the status bar
        status_inner_frame = ttk.Frame(status_frame, style='StatusBar.TFrame')
        status_inner_frame.pack(fill=tk.X, expand=True, pady=0, ipady=5)
        
        # Status indicator with icon
        status_indicator_frame = ttk.Frame(status_inner_frame)
        status_indicator_frame.pack(side=tk.LEFT, padx=10)
        
        self.status_icon_label = ttk.Label(status_indicator_frame, text="●", font=('Segoe UI', 12))
        self.status_icon_label.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(status_indicator_frame, text="Status:", style='Status.TLabel').pack(side=tk.LEFT)
        status_value_label = ttk.Label(status_indicator_frame, textvariable=self.status_var)
        status_value_label.pack(side=tk.LEFT, padx=5)
        
        # Separator
        ttk.Separator(status_inner_frame, orient='vertical').pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=2)
        
        # Packet counter with icon
        packet_frame = ttk.Frame(status_inner_frame)
        packet_frame.pack(side=tk.LEFT)
        ttk.Label(packet_frame, text="📊", font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(packet_frame, textvariable=self.packet_count_var, style='Status.TLabel').pack(side=tk.LEFT)

        # Device stats
        stats_frame = ttk.Frame(status_inner_frame)
        stats_frame.pack(side=tk.RIGHT, padx=10)
        ttk.Label(stats_frame, text="📱", font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(stats_frame, textvariable=self.stats_var, style='Status.TLabel').pack(side=tk.LEFT)

        # Style for status icon - will update with the monitoring state
        self.status_icon_label.configure(foreground=self.neutral_color)
        
        # Create notebook for tabs with custom styling
        style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.light_accent, padding=(12, 6), font=('Segoe UI', 10))
        style.map("TNotebook.Tab",
                background=[("selected", self.accent_color)],
                foreground=[("selected", "white")],
                expand=[("selected", [1, 1, 1, 0])])
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Improved Device Tab
        devices_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(devices_frame, text="Devices")
        
        # Create header and info for the devices tab
        devices_header_frame = ttk.Frame(devices_frame)
        devices_header_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(devices_header_frame, text="Network Devices", 
          style='Subheader.TLabel').pack(side=tk.LEFT)

        ttk.Label(devices_header_frame, 
                text="Devices detected on your network. Suspicious devices are highlighted in red.", 
                style='Status.TLabel', foreground='red').pack(side=tk.LEFT, padx=(10, 0))

        # Create device table with improved styling
        device_table_frame = ttk.Frame(devices_frame)
        device_table_frame.pack(fill=tk.BOTH, expand=True)
        
        device_columns = ('ip', 'mac', 'first_seen', 'last_seen', 'count')
        self.device_tree = ttk.Treeview(device_table_frame, columns=device_columns, 
                                       show='headings', height=15)
        
        # Define headings with custom styling
        self.device_tree.heading('ip', text='IP Address')
        self.device_tree.heading('mac', text='MAC Address')
        self.device_tree.heading('first_seen', text='First Seen')
        self.device_tree.heading('last_seen', text='Last Seen')
        self.device_tree.heading('count', text='Packet Count')
        
        # Define columns with better proportions
        self.device_tree.column('ip', width=120, minwidth=100)
        self.device_tree.column('mac', width=160, minwidth=140)
        self.device_tree.column('first_seen', width=160, minwidth=140)
        self.device_tree.column('last_seen', width=160, minwidth=140)
        self.device_tree.column('count', width=100, minwidth=80)
        
        # Add scrollbars
        device_y_scrollbar = ttk.Scrollbar(device_table_frame, orient="vertical", 
                                         command=self.device_tree.yview)
        device_x_scrollbar = ttk.Scrollbar(device_table_frame, orient="horizontal", 
                                         command=self.device_tree.xview)
        
        self.device_tree.configure(yscrollcommand=device_y_scrollbar.set,
                                 xscrollcommand=device_x_scrollbar.set)
        
        # Pack elements with proper scrollbar placement
        self.device_tree.grid(row=0, column=0, sticky='nsew')
        device_y_scrollbar.grid(row=0, column=1, sticky='ns')
        device_x_scrollbar.grid(row=1, column=0, sticky='ew')
        
        device_table_frame.grid_rowconfigure(0, weight=1)
        device_table_frame.grid_columnconfigure(0, weight=1)
        
        # Alerts Tab
        alerts_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(alerts_frame, text="Alerts")
        
        # Alert controls
        alert_control_frame = ttk.Frame(alerts_frame)
        alert_control_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.clear_alerts_btn = ttk.Button(alert_control_frame, text="Clear Alerts", 
                                       command=self.clear_alerts, style='Action.TButton')
        self.clear_alerts_btn.pack(side=tk.RIGHT)
        
        # Create alerts table
        alert_columns = ('timestamp', 'ip', 'old_mac', 'new_mac', 'time_diff')
        self.alert_tree = ttk.Treeview(alerts_frame, columns=alert_columns, show='headings')
        
        # Define headings
        self.alert_tree.heading('timestamp', text='Timestamp')
        self.alert_tree.heading('ip', text='IP Address')
        self.alert_tree.heading('old_mac', text='Old MAC')
        self.alert_tree.heading('new_mac', text='New MAC')
        self.alert_tree.heading('time_diff', text='Time Difference')
        
        # Define columns
        self.alert_tree.column('timestamp', width=150)
        self.alert_tree.column('ip', width=120)
        self.alert_tree.column('old_mac', width=150)
        self.alert_tree.column('new_mac', width=150)
        self.alert_tree.column('time_diff', width=100)
        
        # Add scrollbar
        alert_scrollbar = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=alert_scrollbar.set)
        
        # Pack elements
        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alert_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enhanced Dashboard Tab with scrollbar
        dashboard_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Create a canvas and scrollbar for scrolling
        dashboard_canvas = tk.Canvas(dashboard_frame, background=self.bg_color)
        dashboard_scrollbar = ttk.Scrollbar(dashboard_frame, orient="vertical", command=dashboard_canvas.yview)

        # Create a frame inside canvas to hold the content
        scrollable_frame = ttk.Frame(dashboard_canvas,)
        scrollable_frame.bind(
            "<Configure>",
            lambda e: dashboard_canvas.configure(scrollregion=dashboard_canvas.bbox("all"))
        )

        # Create window in canvas
        dashboard_canvas.create_window((0, 0), window=scrollable_frame, anchor="n")
        dashboard_canvas.configure(yscrollcommand=dashboard_scrollbar.set)

        # Pack the canvas and scrollbar
        dashboard_canvas.pack(side="left", fill="both", expand=True)
        dashboard_scrollbar.pack(side="left", fill="y")

        # Configure canvas scrolling with mousewheel
        def _on_mousewheel(event):
            dashboard_canvas.yview_scroll(-1 * int(event.delta/120), "units")
        dashboard_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Add dashboard header
        dashboard_header_frame = ttk.Frame(scrollable_frame)
        dashboard_header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(dashboard_header_frame, text="Network Activity Dashboard", 
                style='Subheader.TLabel').pack(side=tk.LEFT)
        ttk.Label(dashboard_header_frame, 
                text="Visual representation of network traffic and device activity", 
                style='Status.TLabel', foreground='black').pack(side=tk.LEFT, padx=(10, 0))
        
        # Create chart areas with better styling
        # Packet count over time chart (top chart)
        time_chart_frame = ttk.LabelFrame(scrollable_frame, text="Packet Traffic Over Time", padding=10)
        time_chart_frame.pack(fill=tk.X, pady=(0, 15), ipady=5 )
        
        # Improved time series chart
        self.time_fig = Figure(figsize=(6, 2.5), dpi=100, facecolor=self.bg_color)
        self.time_chart = self.time_fig.add_subplot(111)
        self.time_chart.set_title('Packet Count Over Time', fontsize=12, color=self.text_color)
        self.time_chart.set_xlabel('Time', fontsize=10, color=self.text_color)
        self.time_chart.set_ylabel('Packets', fontsize=10, color=self.text_color)
        self.time_chart.tick_params(colors=self.text_color)
        self.time_chart.grid(True, linestyle='--', alpha=0.7)
        
        self.time_canvas = FigureCanvasTkAgg(self.time_fig, master=time_chart_frame)
        self.time_canvas.draw()
        self.time_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Device activity chart (bottom chart)
        device_chart_frame = ttk.LabelFrame(scrollable_frame, text="Top Device Activity", padding=10)
        device_chart_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5), ipady=5)
        
        # Improved device activity chart
        self.fig = Figure(figsize=(6, 4), dpi=100, facecolor=self.bg_color)
        self.chart = self.fig.add_subplot(111)
        self.chart.set_title('Top Device Activity by Packet Count', fontsize=12, color=self.text_color)
        self.chart.set_xlabel('IP Address', fontsize=10, color=self.text_color)
        self.chart.set_ylabel('Packet Count', fontsize=10, color=self.text_color)
        self.chart.tick_params(colors=self.text_color)
        self.chart.grid(True, axis='y', linestyle='--', alpha=0.7)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=device_chart_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Log Tab
        log_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(log_frame, text="Logs")
        
        # Create log controls
        log_control_frame = ttk.Frame(log_frame)
        log_control_frame.pack(fill=tk.X, pady=(0, 5))
                 
        self.copy_log_btn = ttk.Button(log_control_frame, text="Copy Log", 
                                   command=self.copy_log, style='Action.TButton')
        self.copy_log_btn.pack(side=tk.RIGHT, padx=5)
        
        self.clear_log_btn = ttk.Button(log_control_frame, text="Clear Log", 
                                    command=self.clear_log, style='Action.TButton')
        self.clear_log_btn.pack(side=tk.RIGHT)
        
        # Create log text area with custom styling
        log_font = Font(family="Consolas", size=9)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=log_font, 
                                            background="#f8f8f8", foreground="#333333")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for log levels
        self.log_text.tag_configure("error", foreground="red", font=Font(family="Consolas", size=9, weight="bold"))
        self.log_text.tag_configure("warning", foreground="orange", font=Font(family="Consolas", size=9))
        self.log_text.tag_configure("info", foreground="#333333", font=Font(family="Consolas", size=9))
        
        # Set initial state to disabled (will be enabled when appending text)
        self.log_text.configure(state="disabled")
    
    def clear_alerts(self):
        """Clear the alert tree and detector alerts"""
        if messagebox.askyesno("Clear Alerts", "Are you sure you want to clear all alerts?"):
            # Clear the tree
            for item in self.alert_tree.get_children():
                self.alert_tree.delete(item)
                
            # Clear the detector's suspicious activities
            with self.detector.lock:
                self.detector.suspicious_activities.clear()
                
            # Update stats
            self.update_stats()
            
    def copy_log(self):
        """Copy log contents to clipboard"""
        log_content = self.log_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(log_content)
        self.root.update()  # Required to finalize clipboard update
        messagebox.showinfo("Log Copied", "Log content has been copied to clipboard")
    
    def clear_log(self):
        """Clear the log text area"""
        if messagebox.askyesno("Clear Log", "Are you sure you want to clear the log?"):
            self.log_text.configure(state="normal")
            self.log_text.delete(1.0, tk.END)
            self.log_text.configure(state="disabled")
            logging.info("Log cleared")
        
    def get_available_interfaces(self):
        """Get list of available network interfaces using names if possible."""
        interfaces = ["Default (Auto-detect)"]  # Always include auto-detect option first
        self.interface_mapping = {}  # Create a mapping to store interface information
        
        try:
            # First try using platform-specific methods for better reliability
            if platform.system() == "Windows":
                logging.info("Detecting Windows network interfaces")
                # Try using Scapy's Windows utilities first
                if scapy_if_list:
                    for iface_dict in scapy_if_list:
                        try:
                            name = iface_dict.get('description') or iface_dict.get('name') or ""
                            guid = iface_dict.get('guid', '')
                            
                            # Skip loopback interfaces
                            if ('loopback' in name.lower() or 'loopback' in guid.lower() or 
                                'microsoft' in name.lower()):
                                continue
                                
                            # Create a display name and store in the mapping
                            display_name = f"{name} ({guid})" if guid else name
                            self.interface_mapping[display_name] = guid
                            
                            # Prioritize Wi-Fi and Ethernet interfaces
                            if ('Wi-Fi' in name or 'Wireless' in name or 'Ethernet' in name):
                                interfaces.insert(1, display_name)  # Add right after auto-detect
                            else:
                                interfaces.append(display_name)
                        except Exception as e:
                            logging.debug(f"Failed to process interface: {e}")
                
            # If we still don't have interfaces beyond the auto-detect, try netifaces
            if len(interfaces) <= 1:
                logging.info("Falling back to netifaces for interface detection")
                for iface in netifaces.interfaces():
                    try:
                        addrs = netifaces.ifaddresses(iface)
                        if netifaces.AF_INET in addrs:  # Has IPv4 address
                            # Get the actual IP to display it
                            ip = addrs[netifaces.AF_INET][0].get('addr', '')
                            if ip == '127.0.0.1':  # Skip loopback
                                continue
                                
                            display_name = f"Interface {iface} - {ip}"
                            self.interface_mapping[display_name] = iface
                            interfaces.append(display_name)
                    except Exception as e:
                        logging.debug(f"Error with interface {iface}: {e}")
            
            # Sort interfaces to put active ones first (ones with IP addresses)
            if len(interfaces) > 1:
                # Keep Default as first, then sort the rest
                default = interfaces[0]
                rest = interfaces[1:]
                
                # Try to get those with IPs to the top
                def get_priority(iface_name):
                    if "Wi-Fi" in iface_name:
                        return 1
                    elif "Ethernet" in iface_name:
                        return 2
                    else:
                        return 3
                        
                rest.sort(key=get_priority)
                interfaces = [default] + rest
                        
            logging.info(f"Found {len(interfaces)-1} network interfaces besides auto-detect")
            
            # Handle case where no interfaces are found
            if len(interfaces) <= 1:
                logging.warning("No network interfaces found, adding fallback option")
                interfaces.append("Network interface detection failed")
                
        except Exception as e:
            logging.error(f"Error detecting interfaces: {e}")
            interfaces.append("Interface detection error")
        
        return interfaces

    def get_selected_interface_for_scapy(self):
        """Gets the interface identifier Scapy is most likely to understand."""
        try:
            selected_display_name = self.interface_var.get()
            
            # If using the auto-detect option
            if selected_display_name == "Default (Auto-detect)":
                default_iface = self.detector.get_default_interface()
                logging.info(f"Using auto-detected default interface: {default_iface}")
                return default_iface
    
            # Check if we have it in our mapping
            if hasattr(self, 'interface_mapping') and selected_display_name in self.interface_mapping:
                guid = self.interface_mapping[selected_display_name]
                logging.info(f"Using mapped interface GUID: {guid}")
                return guid
    
            # Extract GUID for Windows systems - this is usually more reliable
            if '(' in selected_display_name and ')' in selected_display_name:
                guid = selected_display_name.split('(')[1].split(')')[0]
                guid = guid.strip()
                logging.info(f"Extracted GUID from interface name: {guid}")
                return guid
    
            # Final fallback: return the raw selection (might be just a name or GUID)
            logging.info(f"Using raw interface name: {selected_display_name}")
            return selected_display_name
        except Exception as e:
            logging.error(f"Error identifying interface: {e}")
            return None

    def scan_network(self, event=None):
        """Perform a network scan with better feedback and error handling"""
        # Prevent multiple scans at once
        if hasattr(self, 'scanning') and self.scanning:
            messagebox.showinfo("Scan in Progress", "A network scan is already in progress")
            return
        
        self.scanning = True
        self.status_var.set("Scanning network...")
        self.status_icon_label.configure(foreground="#ffa500")  # Orange for in-progress
        self.root.update()
        
        # Update UI to show scanning state
        self.scan_btn.configure(text="⏳ Scanning...", state='disabled')
        
        # Create a progress indicator
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Network Scan")
        progress_window.geometry("300x150")
        progress_window.transient(self.root)
        progress_window.grab_set()
        progress_window.configure(bg=self.bg_color)
        
        # Position in center of parent window
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 150
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 75
        progress_window.geometry(f"+{x}+{y}")
        
        # Add progress components
        frame = ttk.Frame(progress_window, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Scanning Network", 
                font=('Segoe UI', 12, 'bold')).pack(pady=(0, 10))
        ttk.Label(frame, text="Please wait while scanning all devices").pack(pady=5)
        
        progress = ttk.Progressbar(frame, mode='indeterminate', length=250)
        progress.pack(pady=10)
        progress.start(10)
        
        # Cancel button
        cancel_button = ttk.Button(frame, text="Cancel", command=lambda: self._cancel_scan(progress_window))
        cancel_button.pack()
        
        selected_iface = self.interface_var.get()
        logging.info(f"Starting network scan with selected interface: {selected_iface}")
        
        # Track scan state
        self.scan_cancelled = False
        
        # Run scan in a separate thread to avoid UI freezing
        def run_scan():
            try:
                # Reset detector data when switching interfaces
                with self.detector.lock:
                    self.detector.ip_mac_mappings.clear()
                    self.detector.total_packets = 0  # Reset packet counter
                self.detector.suspicious_activities.clear()
                
                # Use the interface selector function to get the best interface identifier for Scapy
                interface_for_scapy = self.get_selected_interface_for_scapy()
                logging.info(f"Using interface identifier for scan: {interface_for_scapy}")
                
                # Try to scan with the specified interface
                success = False
                if not self.scan_cancelled:
                    success = self.detector.scan_network(interface_for_scapy)
                
                # If that failed, try with no interface specified (fallback mode)
                if not success and interface_for_scapy is not None and not self.scan_cancelled:
                    logging.info("First scan attempt failed, trying without interface specification")
                    success = self.detector.scan_network(None)
                
                # Update UI with scan results
                if self.scan_cancelled:
                    self.status_var.set("Network scan cancelled")
                    self.show_toast_notification("Scan Cancelled", "Network scan was cancelled", self.neutral_color)
                elif success:
                    self.status_var.set("Network scan complete")
                    # Reset packet count tracking for charts
                    self.chart_data = {"timestamps": [], "packet_counts": []}
                    self.show_toast_notification("Scan Complete", f"Found {self.detector.get_device_count()} devices", self.success_color)
                else:
                    self.status_var.set("Network scan failed")
                    self.show_toast_notification("Scan Failed", "Could not complete network scan. Check logs for details.", self.alert_color)
                    
                # Update tables and stats if not cancelled
                if not self.scan_cancelled:
                    self.update_device_table()
                    self.update_stats()
                    
            except Exception as e:
                logging.error(f"Error during network scan: {e}")
                self.status_var.set("Network scan error")
            finally:
                # Reset UI state
                self.root.after(0, lambda: self._complete_scan(progress_window))
        
        threading.Thread(target=run_scan, daemon=True).start()
        
    def _cancel_scan(self, progress_window):
        """Cancel a running network scan"""
        self.scan_cancelled = True
        progress_window.destroy()
        self.scan_btn.configure(text="🔍 Scan Network", state='normal')
        self.scanning = False
        self.status_icon_label.configure(foreground=self.neutral_color)
        
    def _complete_scan(self, progress_window):
        """Complete the network scan and clean up UI"""
        # Handle the case where window was already closed by user
        try:
            if progress_window.winfo_exists():
                progress_window.destroy()
        except:
            pass
            
        # Reset scanning state
        self.scan_btn.configure(text="🔍 Scan Network", state='normal')
        self.scanning = False
        self.status_icon_label.configure(foreground=self.neutral_color)
    
    def toggle_monitoring(self):
        """Toggle network monitoring on/off. Returns True if started/stopped successfully."""
        if not self.is_monitoring:
            # Start monitoring
            interface_for_scapy = self.get_selected_interface_for_scapy()
            if not interface_for_scapy or "Error" in interface_for_scapy or "No suitable" in interface_for_scapy:
                messagebox.showerror("Error", "Please select a valid network interface")
                return False

            # Pass the potentially better identifier to the detector
            success = self.detector.start_sniffing(interface_for_scapy)
            if success:
                self.is_monitoring = True
                self.status_var.set(f"Monitoring on {interface_for_scapy}")
                self.monitor_btn.configure(text="⏹ Stop Monitoring", style='Stop.TButton')
                
                # Visual feedback - update status icon
                self.status_icon_label.configure(foreground=self.success_color)
                
                # Disable interface selection
                for child in self.monitor_btn.master.winfo_children():
                    if isinstance(child, ttk.Combobox):
                        child.configure(state='disabled')
                
                # Start recording for time chart
                self.chart_data["timestamps"].append(datetime.now().strftime('%H:%M:%S'))
                self.chart_data["packet_counts"].append(0)
                
                # Show a toast notification
                self.show_toast_notification(
                    "Monitoring Started", 
                    f"Now monitoring traffic on {interface_for_scapy}",
                    self.success_color
                )
                
                return True
            else:
                messagebox.showerror("Error", f"Failed to start monitoring on {interface_for_scapy}")
                return False
        else:
            # Stop monitoring
            self.detector.stop_sniffing()
            self.is_monitoring = False
            self.status_var.set("Monitoring stopped")
            self.monitor_btn.configure(text="▶ Start Monitoring", style='Action.TButton')
            
            # Visual feedback - update status icon
            self.status_icon_label.configure(foreground=self.neutral_color)
            
            # Enable interface selection
            for child in self.monitor_btn.master.winfo_children():
                if isinstance(child, ttk.Combobox):
                    child.configure(state='normal')
                    
            # Also ensure simulation stops if monitoring stops
            if self.is_simulating:
                self.detector.stop_simulation()
                self.is_simulating = False
                self.simulate_btn.configure(text="⚠ Simulate Attack")
                
            # Show a toast notification
            self.show_toast_notification(
                "Monitoring Stopped", 
                "Network traffic monitoring has been stopped",
                self.neutral_color
            )
                
            return True
            
    def show_toast_notification(self, title, message, color=None):
        """Show a temporary toast notification at the bottom of the screen"""
        # Create the toast frame
        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)  # Remove window decorations
        
        # Set toast position at the bottom right of main window
        x = self.root.winfo_x() + self.root.winfo_width() - 340
        y = self.root.winfo_y() + self.root.winfo_height() - 120
        toast.geometry(f"300x80+{x}+{y}")
        
        # Set toast background
        bg_color = color if color else self.accent_color
        toast.configure(background=bg_color)
        
        # Add content
        toast_frame = ttk.Frame(toast, padding=10)
        toast_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(toast_frame, text=title, 
                font=('Segoe UI', 11, 'bold')).pack(anchor='w')
        ttk.Label(toast_frame, text=message,
                wraplength=280).pack(anchor='w', pady=(5, 0))
        
        # Auto-close after 3 seconds
        toast.after(3000, toast.destroy)
    
    def update_status(self):
        """Update UI status and information"""
        if self.is_monitoring:
            # Refresh data
            self.update_device_table()
            self.update_alert_table()
            self.update_stats()
            self.update_chart()
            
            # Update total packet count
            total_packets = self.detector.get_total_packet_count()
            self.packet_count_var.set(f"Total Packets: {total_packets}")
            
            # Add data point for time chart (every 5 seconds)
            current_time = datetime.now()
            if not self.chart_data["timestamps"] or (current_time - datetime.strptime(self.chart_data["timestamps"][-1], '%H:%M:%S')).total_seconds() >= 5:
                self.chart_data["timestamps"].append(current_time.strftime('%H:%M:%S'))
                self.chart_data["packet_counts"].append(total_packets)
                # Keep only last 30 data points
                if len(self.chart_data["timestamps"]) > 30:
                    self.chart_data["timestamps"].pop(0)
                    self.chart_data["packet_counts"].pop(0)
            
            # Update status icon to show active monitoring
            self.status_icon_label.configure(foreground=self.success_color)
        else:
            # Reset status icon when not monitoring
            self.status_icon_label.configure(foreground=self.neutral_color)
        
        # Schedule next update
        self.root.after(1000, self.update_status)
    
    def update_device_table(self):
        """Update the device table with current data"""
        # Clear existing items
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
            
        # Add current items
        mappings = self.detector.get_ip_mac_mappings()
        for ip, info in mappings.items():
            # Convert timestamps
            first_seen = datetime.fromtimestamp(info.get('first_time', info.get('time', 0))).strftime('%Y-%m-%d %H:%M:%S')
            last_seen = datetime.fromtimestamp(info.get('time', 0)).strftime('%Y-%m-%d %H:%M:%S')
            
            # Add item with proper styling for suspicious MAC addresses
            item_id = self.device_tree.insert('', tk.END, values=(
                ip,
                info.get('mac', 'Unknown'),
                first_seen,
                last_seen,
                info.get('count', 0)
            ))
            
            # If this IP is in suspicious activities, highlight it
            if any(activity.get('ip') == ip for activity in self.detector.get_suspicious_activities()):
                self.device_tree.item(item_id, tags=('suspicious',))
        
        # Configure tag for suspicious items
        self.device_tree.tag_configure('suspicious', background='#ffcccc')
    
    def update_alert_table(self):
        """Update the alert table with current data"""
        # Store current selection
        selected_items = self.alert_tree.selection()
        selected_values = [self.alert_tree.item(item, 'values') for item in selected_items]
        
        # Clear existing items
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
            
        # Add new alerts
        activities = self.detector.get_suspicious_activities()
        
        # Create a set of existing timestamps to avoid duplicates
        added_timestamps = set()
        
        # Sort activities by timestamp, newest first
        sorted_activities = sorted(activities, 
                                  key=lambda x: datetime.strptime(x.get('timestamp', '1970-01-01 00:00:00'), 
                                                                '%Y-%m-%d %H:%M:%S'), 
                                  reverse=True)
        
        for activity in sorted_activities:
            timestamp = activity.get('timestamp', '')
            
            # Skip if we've already added this timestamp
            if timestamp in added_timestamps:
                continue
            
            added_timestamps.add(timestamp)
            
            # Add item with proper styling
            item_id = self.alert_tree.insert('', tk.END, values=(
                timestamp,
                activity.get('ip', ''),
                activity.get('old_mac', ''),
                activity.get('new_mac', ''),
                activity.get('time_diff', '')
            ))
            
            # Add styling for recent alerts (less than 60 seconds old)
            try:
                time_diff = (datetime.now() - datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')).total_seconds()
                if time_diff < 60:
                    self.alert_tree.item(item_id, tags=('recent',))
                elif time_diff < 300:  # Less than 5 minutes
                    self.alert_tree.item(item_id, tags=('recent_older',))
            except Exception:
                pass  # Skip if timestamp format is invalid
        
        # Configure tags for alerts
        self.alert_tree.tag_configure('recent', background='#ff9999')
        self.alert_tree.tag_configure('recent_older', background='#ffe6e6')
        
        # Restore selection if items still exist
        for values in selected_values:
            if values:
                for item in self.alert_tree.get_children():
                    if self.alert_tree.item(item, 'values')[0] == values[0]:
                        self.alert_tree.selection_add(item)
                        self.alert_tree.see(item)
                        break
        
        # Show notification for the most recent alert only if we're not at max alerts
        if activities and self.is_monitoring and self.active_alerts < self.max_alerts:
            newest_activity = sorted_activities[0] if sorted_activities else None
            # Check if this is a new alert (within last 10 seconds)
            if newest_activity:
                try:
                    time_diff = (datetime.now() - datetime.strptime(newest_activity.get('timestamp', ''), 
                                                                 '%Y-%m-%d %H:%M:%S')).total_seconds()
                    if time_diff < 10:  # New alert within last 10 seconds
                        self.show_alert_notification(newest_activity)
                except Exception:
                    pass  # Skip if timestamp format is invalid
    
    def update_stats(self):
        """Update statistics display"""
        device_count = self.detector.get_device_count()
        suspicious_count = self.detector.get_suspicious_count()
        self.stats_var.set(f"Devices: {device_count} | Suspicious: {suspicious_count}")
    
    def update_chart(self):
        """Update the dashboard charts"""
        # Update packet count over time chart
        self.time_chart.clear()
        if len(self.chart_data["timestamps"]) > 1:
            self.time_chart.plot(
                range(len(self.chart_data["timestamps"])), 
                self.chart_data["packet_counts"],
                marker='o', 
                linestyle='-', 
                color=self.accent_color
            )
            # Show only every Nth label to avoid overcrowding
            step = max(1, len(self.chart_data["timestamps"]) // 10)
            self.time_chart.set_xticks(range(0, len(self.chart_data["timestamps"]), step))
            self.time_chart.set_xticklabels([self.chart_data["timestamps"][i] for i in range(0, len(self.chart_data["timestamps"]), step)])
            self.time_chart.set_title('Packet Count Over Time')
            self.time_chart.grid(True, linestyle='--', alpha=0.7)
            self.time_fig.tight_layout()
            self.time_canvas.draw()
        
        # Update device activity chart
        # Get data from detector
        mappings = self.detector.get_ip_mac_mappings()
        
        # Extract data for charting
        ips = list(mappings.keys())
        counts = [info.get('count', 0) for info in mappings.values()]
        
        # Clear existing chart
        self.chart.clear()
        
        # Create new chart (limit to top 10 for readability)
        if ips:
            # Sort by count
            combined = sorted(zip(ips, counts), key=lambda x: x[1], reverse=True)
            top_ips = [x[0] for x in combined[:10]]
            top_counts = [x[1] for x in combined[:10]]
            
            # Use different colors for suspicious IPs
            colors = []
            for ip in top_ips:
                if any(activity.get('ip') == ip for activity in self.detector.get_suspicious_activities()):
                    colors.append(self.alert_color)
                else:
                    colors.append(self.accent_color)
            
            # Create bar chart
            bars = self.chart.bar(top_ips, top_counts, color=colors)
            self.chart.set_title('Top 10 Device Activity')
            self.chart.set_xlabel('IP Address')
            self.chart.set_ylabel('Packet Count')
            self.chart.tick_params(axis='x', rotation=45)
            self.chart.grid(True, axis='y', linestyle='--', alpha=0.7)
            self.fig.tight_layout()
            
        # Redraw
        self.canvas.draw()
    
    def show_alert_notification(self, activity):
        """Show a notification for a new alert"""
        # Create a popup notification
        self.active_alerts += 1
        alert_window = tk.Toplevel(self.root)
        alert_window.title("⚠️ ARP Spoofing Alert!")
        alert_window.geometry("450x220")
        alert_window.attributes('-topmost', True)
        alert_window.configure(bg="#ffe6e6")
        
        # Add alert info
        frame = ttk.Frame(alert_window, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)
        
        alert_icon = ttk.Label(frame, text="⚠️", font=('Segoe UI', 24), foreground=self.alert_color)
        alert_icon.pack(pady=(0, 5))
        
        ttk.Label(frame, text="POSSIBLE ARP SPOOFING DETECTED!", 
                  font=('Segoe UI', 12, 'bold'), foreground=self.alert_color).pack(pady=5)
        
        # Format IP and MAC for better readability
        ip = activity.get('ip', 'Unknown IP')
        old_mac = activity.get('old_mac', 'Unknown')
        new_mac = activity.get('new_mac', 'Unknown')
        time_diff = activity.get('time_diff', 'Unknown time')
        
        message = f"IP {ip} changed MAC address\nFrom: {old_mac}\nTo: {new_mac}\nTime difference: {time_diff}"
        ttk.Label(frame, text=message, wraplength=400).pack(pady=5)
        
        # Add timestamp
        ttk.Label(frame, text=f"Detected at: {activity.get('timestamp', '')}", 
                  style='Status.TLabel').pack(pady=(5, 10))
        
        # Button frame
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=5)
        
        def close_alert():
            self.active_alerts -= 1
            alert_window.destroy()
        
        def view_details():
            close_alert()
            # Switch to alerts tab
            for i, tab_name in enumerate(self.notebook.tabs()):
                if self.notebook.tab(tab_name, "text") == "Alerts":
                    self.notebook.select(i)
                    break
            # Select the alert in the tree
            for item in self.alert_tree.get_children():
                if self.alert_tree.item(item, 'values')[0] == activity.get('timestamp', ''):
                    self.alert_tree.selection_set(item)
                    self.alert_tree.focus(item)
                    self.alert_tree.see(item)
                    break
        
        ttk.Button(button_frame, text="View Details", command=view_details, 
                  style='Action.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=close_alert, 
                  style='Action.TButton').pack(side=tk.LEFT, padx=5)
        
        # Auto-close after 20 seconds
        alert_window.after(20000, close_alert)
    
    def show_simulation_dialog(self):
        """Show dialog for simulating an ARP spoofing attack"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Simulate ARP Spoofing Attack")
        dialog.geometry("450x220")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.bg_color)
        
        frame = ttk.Frame(dialog, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(frame, text="ARP Spoofing Simulation", font=('Segoe UI', 12, 'bold')).grid(
            row=0, column=0, columnspan=2, pady=(0, 10), sticky=tk.W)
        
        # Target IP
        ttk.Label(frame, text="Target IP:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        target_ip_var = tk.StringVar()
        target_ip_entry = ttk.Entry(frame, textvariable=target_ip_var, width=25)
        target_ip_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Get default gateway as suggestion
        default_gateway = self.detector.get_default_gateway()
        if default_gateway:
            target_ip_var.set(default_gateway)
        
        # Spoof IP (to impersonate)
        ttk.Label(frame, text="Spoof IP:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        spoof_ip_var = tk.StringVar()
        spoof_ip_entry = ttk.Entry(frame, textvariable=spoof_ip_var, width=25)
        spoof_ip_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Warning label
        ttk.Label(frame, text="WARNING: This is for educational purposes only.", 
                foreground=self.alert_color, font=('Segoe UI', 9, 'bold')).grid(
                    row=3, column=0, columnspan=2, pady=10, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky=tk.E)
        
        ttk.Button(button_frame, text="Simulate Attack", style='Action.TButton', command=lambda: self.start_simulation_thread(
            target_ip_var.get(), spoof_ip_var.get(), dialog
        )).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def start_simulation_thread(self, target_ip, spoof_ip, dialog):
        """Start the simulation in a separate thread."""
        if not target_ip or not spoof_ip:
            messagebox.showerror("Input Error", "Please enter both Target IP and Spoof IP.", parent=dialog)
            return

        interface_for_scapy = self.get_selected_interface_for_scapy()
        if not interface_for_scapy or "Error" in interface_for_scapy or "No suitable" in interface_for_scapy:
            messagebox.showerror("Interface Error", "Please select a valid network interface.", parent=dialog)
            return

        dialog.destroy()
        if messagebox.askyesno(
            "Confirm Simulation",
            f"This will simulate an ARP spoofing attack, telling {target_ip} that this machine is {spoof_ip} for 10 seconds using interface '{interface_for_scapy}'.\n\n"
            f"Ensure monitoring is active to detect it.\n"
            f"This is for educational purposes only. Continue?"
        ):
            # Make sure monitoring is active
            if not self.is_monitoring:
                messagebox.showinfo("Info", "Monitoring is not active. Starting monitoring first to detect the simulation.")
                if not self.toggle_monitoring():
                    messagebox.showerror("Error", "Failed to start monitoring. Cannot run simulation.")
                    return

            # Run simulation in thread
            def run_simulation():
                self.is_simulating = True
                self.simulate_btn.configure(text="Stop Simulation", style='Stop.TButton')
                self.status_var.set(f"Simulating attack on {interface_for_scapy}: {target_ip} <- {spoof_ip}...")

                success = self.detector.simulate_arp_spoof(target_ip, spoof_ip, interface_for_scapy, duration=10)

                if success:
                    self.root.after(11000, self.check_simulation_status)
                else:
                    self.status_var.set("Attack simulation failed to start.")
                    self.is_simulating = False
                    self.simulate_btn.configure(text="Simulate Attack", style='Action.TButton')

            threading.Thread(target=run_simulation, daemon=True).start()
    
    def check_simulation_status(self):
        """Update status after simulation duration if it wasn't manually stopped."""
        if self.is_simulating:
            self.status_var.set("Attack simulation finished.")
            self.is_simulating = False
            self.simulate_btn.configure(text="Simulate Attack", style='Action.TButton')
    
    def export_data(self):
        """Export detection data to a file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Data"
        )
        
        if not filename:
            return
            
        try:
            with open(filename, 'w') as f:
                # Write header
                f.write("ARP Spoofing Detection Data Export\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Packets Monitored: {self.detector.get_total_packet_count()}\n")
                f.write("-" * 80 + "\n\n")
                
                # Write device data
                f.write("DETECTED DEVICES\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'IP Address':<16} {'MAC Address':<18} {'First Seen':<22} {'Last Seen':<22} {'Packet Count':<12}\n")
                f.write("-" * 80 + "\n")
                
                mappings = self.detector.get_ip_mac_mappings()
                for ip, info in mappings.items():
                    first_seen = datetime.fromtimestamp(info.get('first_time', info.get('time', 0))).strftime('%Y-%m-%d %H:%M:%S')
                    last_seen = datetime.fromtimestamp(info.get('time', 0)).strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"{ip:<16} {info.get('mac', 'Unknown'):<18} {first_seen:<22} {last_seen:<22} {info.get('count', 0):<12}\n")
                
                f.write("\n\n")
                
                # Write alert data
                f.write("SUSPICIOUS ACTIVITIES\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'Timestamp':<22} {'IP Address':<16} {'Old MAC':<18} {'New MAC':<18} {'Time Diff':<12}\n")
                f.write("-" * 80 + "\n")
                
                activities = self.detector.get_suspicious_activities()
                for activity in activities:
                    f.write(f"{activity.get('timestamp', ''):<22} {activity.get('ip', ''):<16} {activity.get('old_mac', ''):<18} ")
                    f.write(f"{activity.get('new_mac', ''):<18} {activity.get('time_diff', ''):<12}\n")
                    
            messagebox.showinfo("Export Complete", f"Data successfully exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting data: {e}")

class TextRedirector:
    """A class to redirect stdout to a tkinter text widget"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.buffer = ""
        self.max_lines = 1000  # Maximum number of lines to keep in the log
        
    def write(self, string):
        if not string:  # Skip empty strings
            return
            
        try:
            if not self.text_widget.winfo_exists():
                return  # Widget has been destroyed
                
            self.buffer += string
            
            # Batch updates to improve performance
            if "\n" in string:
                self.text_widget.configure(state="normal")
                
                # Add timestamp for new lines, if not just a continuation
                lines = string.split("\n")
                timestamp = datetime.now().strftime('[%H:%M:%S] ')
                
                for i, line in enumerate(lines):
                    if not line and i == len(lines) - 1:  # Skip empty last line
                        continue
                        
                    # Add timestamp for each new line except empty ones
                    if line:
                        # Only add timestamp at the start of a message or after newline
                        if i > 0 or self.buffer.endswith('\n'):
                            self.text_widget.insert("end", timestamp + line + "\n")
                        else:
                            self.text_widget.insert("end", line + "\n")
                    else:
                        self.text_widget.insert("end", "\n")
                
                # Reset buffer after processing batch
                self.buffer = ""
                
                # Limit the number of lines in the text widget
                self.limit_log_size()
                    
                self.text_widget.see("end")
                self.text_widget.configure(state="disabled")
        except Exception:
            pass  # Suppress errors, especially during shutdown
        
    def limit_log_size(self):
        """Limit log size to the maximum number of lines"""
        try:
            content = self.text_widget.get(1.0, "end-1c")
            lines = content.split("\n")
            
            if len(lines) > self.max_lines:
                # Keep only the last max_lines
                self.text_widget.delete(1.0, "end")
                self.text_widget.insert(1.0, "\n".join(lines[-self.max_lines:]))
        except Exception:
            pass  # Suppress errors
            
    def flush(self):
        # Process any remaining buffer content
        if self.buffer and hasattr(self, 'text_widget') and self.text_widget.winfo_exists():
            try:
                self.text_widget.configure(state="normal")
                self.text_widget.insert("end", self.buffer)
                self.buffer = ""
                self.text_widget.see("end")
                self.text_widget.configure(state="disabled")
            except Exception:
                pass  # Suppress errors

class LogWidgetHandler(logging.Handler):
    """Custom logging handler that outputs to a tkinter Text widget"""
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget
        
    def emit(self, record):
        try:
            msg = self.format(record)
            
            # Add color based on log level
            tag = ""
            if record.levelno >= logging.ERROR:
                tag = "error"
            elif record.levelno >= logging.WARNING:
                tag = "warning"
            elif record.levelno >= logging.INFO:
                tag = "info"
                
            def append():
                try:
                    if not self.text_widget.winfo_exists():
                        return
                    self.text_widget.configure(state="normal")
                    if tag:
                        self.text_widget.insert(tk.END, msg + "\n", tag)
                    else:
                        self.text_widget.insert(tk.END, msg + "\n")
                    self.text_widget.see(tk.END)
                    self.text_widget.configure(state="disabled")
                except Exception:
                    pass  # Widget might have been destroyed
                
            # Schedule the append to run in the main thread
            if self.text_widget.winfo_exists():
                self.text_widget.after(0, append)
        except Exception:
            pass  # Suppress errors during shutdown

def main():
    try:
        root = tk.Tk()
        # Set app icon if available
        try:
            if platform.system() == "Windows":
                root.iconbitmap(default="shield.ico")
            else:
                # For Linux/Mac
                icon = tk.PhotoImage(file="shield.png")
                root.iconphoto(True, icon)
        except Exception:
            # Continue without icon if not found
            pass
        
        # Create the application
        app = ARPSpoofDetectorGUI(root)
        
        # Set up exception handler for the mainloop
        def handle_exception(exc_type, exc_value, exc_traceback):
            logging.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
            messagebox.showerror("Error", f"An error occurred: {exc_value}")
        
        # Install exception hook
        sys.excepthook = handle_exception
        
        # Start the main loop
        root.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
        logging.error(f"Application error: {e}", exc_info=True)
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()