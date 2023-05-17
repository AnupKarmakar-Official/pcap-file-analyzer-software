import tkinter as tk
from tkinter import filedialog

from scapy.all import *
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP, UDP


class PcapAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Pcap Analyzer")

        # Create frame to hold buttons
        button_frame = tk.Frame(master)
        button_frame.pack(pady=10)

        # Create buttons to run analyses
        open_file_button = tk.Button(button_frame, text="Open PCAP File", command=self.open_pcap_file)
        open_file_button.pack(side="left", padx=10)
        analyze_ips_button = tk.Button(button_frame, text="Analyze IPs", command=self.analyze_ips)
        analyze_ips_button.pack(side="left", padx=10)
        analyze_tcp_button = tk.Button(button_frame, text="Analyze TCP Streams", command=self.analyze_tcp_streams)
        analyze_tcp_button.pack(side="left", padx=10)
        analyze_udp_button = tk.Button(button_frame, text="Analyze UDP Streams", command=self.analyze_udp_streams)
        analyze_udp_button.pack(side="left", padx=10)
        analyze_urls_button = tk.Button(button_frame, text="Analyze URLs", command=self.analyze_urls)
        analyze_urls_button.pack(side="left", padx=10)
        analyze_files_button = tk.Button(button_frame, text="Analyze File Contents", command=self.analyze_file_contents)
        analyze_files_button.pack(side="left", padx=10)

        # Create labels to display analysis results
        self.source_ips_label = tk.Label(master, text="Source IPs: ")
        self.source_ips_label.pack()
        self.dest_ips_label = tk.Label(master, text="Destination IPs: ")
        self.dest_ips_label.pack()
        self.tcp_streams_label = tk.Label(master, text="TCP Streams: ")
        self.tcp_streams_label.pack()
        self.udp_streams_label = tk.Label(master, text="UDP Streams: ")
        self.udp_streams_label.pack()
        self.urls_label = tk.Label(master, text="URLs: ")
        self.urls_label.pack()
        self.file_contents_label = tk.Label(master, text="File Contents: ")
        self.file_contents_label.pack()

    def open_pcap_file(self):
        # Open PCAP file using file dialog
        filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                              filetypes=(("PCAP files", "*.pcap"), ("all files", "*.*")))
        # Read packets from PCAP file
        packets = rdpcap(filename)

        # Store packets in class attribute for use in other methods
        self.packets = packets

    def analyze_ips(self):
        # Extract source and destination IP addresses
        source_ips = set()
        dest_ips = set()
        for pkt in self.packets:
            if IP in pkt:
                source_ips.add(pkt[IP].src)
                dest_ips.add(pkt[IP].dst)

        # Display extracted IP addresses in labels
        self.source_ips_label.config(text="Source IPs: " + str(source_ips))
        self.dest_ips_label.config(text="Destination IPs: " + str(dest_ips))

    def analyze_tcp_streams(self):
        # Extract TCP streams
        tcp_streams = set()
        for pkt in self.packets:
            if TCP in pkt and Raw in pkt[TCP]:
                tcp_streams.add(bytes(pkt[TCP].payload))

        # Display extracted TCP streams in label
        self.tcp_streams_label.config(text="TCP Streams: " + str(tcp_streams))

    def analyze_udp_streams(self):
        # Extract UDP streams
        udp_streams = set()
        for pkt in self.packets:
            if UDP in pkt and Raw in pkt[UDP]:
                udp_streams.add(bytes(pkt[UDP].payload))

        # Display extracted UDP streams in label
        self.udp_streams_label.config(text="UDP Streams: " + str(udp_streams))

    def analyze_urls(self):
        # Extract URLs from HTTP packets
        urls = set()
        for pkt in self.packets:
            if HTTP in pkt and pkt.haslayer(Raw):
                urls.add(pkt[HTTP].Host + pkt[HTTP].Path)

        # Display extracted URLs in label
        self.urls_label.config(text="URLs: " + str(urls))

    def analyze_file_contents(self):
        # Extract file contents
        file_contents = set()
        for pkt in self.packets:
            if pkt.haslayer(Raw):
                file_contents.add(pkt[Raw].load)

        # Display extracted file contents in label
        self.file_contents_label.config(text="File Contents: " + str(file_contents))


# Create GUI
root = tk.Tk()
app = PcapAnalyzerGUI(root)
root.mainloop()
