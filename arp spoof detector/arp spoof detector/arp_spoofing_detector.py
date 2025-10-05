#!/usr/bin/env python3
# ARP Spoofing Detector for LAN
# Author: Based on project by A.M.I.S Senarathna

import os
import time
import logging
from datetime import datetime
from scapy.all import ARP, sniff, srp, Ether, send, sendp
import threading
import ipaddress
import netifaces
import platform
from uuid import getnode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='arp_detector.log',
    filemode='a'
)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

class ARPSpoofDetector:
    def __init__(self):
        # Dictionary to store known IP-MAC bindings
        self.ip_mac_mappings = {}
        # Store suspicious activities
        self.suspicious_activities = []
        # Flag to control packet sniffing
        self.running = False
        # Total packet counter
        self.total_packets = 0
        # Lock for thread-safe operations
        self.lock = threading.Lock()
        self.spoofing_thread = None
        self.stop_spoofing_event = threading.Event()

        # Prepopulate this host's own IP→MAC
        try:
            iface = self.get_default_interface()
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs and netifaces.AF_LINK in addrs:
                my_ip = addrs[netifaces.AF_INET][0]['addr']
                my_mac = addrs[netifaces.AF_LINK][0]['addr']
                self.ip_mac_mappings[my_ip] = {
                    'mac': my_mac.lower(),
                    'time': time.time(),
                    'count': 1,
                    'first_time': time.time()
                }
                logging.info(f"Local host mapping initialized: {my_ip} -> {my_mac}")
        except Exception as e:
            logging.warning(f"Could not initialize local host mapping: {e}")
        
    def get_default_gateway(self):
        """Get the default gateway of the system"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            return default_gateway
        except Exception:
            logging.error("Could not determine default gateway")
            return None
            
    def get_default_interface(self):
        """Get the default network interface"""
        try:
            gateways = netifaces.gateways()
            default_iface = gateways['default'][netifaces.AF_INET][1]
            return default_iface
        except Exception:
            logging.error("Could not determine default interface")
            # Try to find any available interface
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface != 'lo' and netifaces.AF_INET in netifaces.ifaddresses(iface):
                    return iface
            return None
            
    def get_network_range(self, iface=None):
        """Get the network range based on the specified interface"""
        try:
            # Use the provided interface if given, otherwise get default
            if not iface:
                iface = self.get_default_interface()
                
            if iface:
                # Try to get interface addresses
                if '(' in iface and ')' in iface:
                    guid = iface.split('(')[1].split(')')[0]
                    try:
                        addrs = netifaces.ifaddresses(guid)
                        iface = guid
                    except Exception:
                        pass
                        
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ipinfo = addrs[netifaces.AF_INET][0]
                        ip = ipinfo['addr']
                        netmask = ipinfo['netmask']
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        logging.info(f"Using network range for interface {iface}: {network}")
                        return str(network)
                except Exception as e:
                    logging.warning(f"Could not get network range for interface {iface}: {e}")
                    
            logging.warning("Using default network range 192.168.1.0/24")
            return "192.168.1.0/24"
        except Exception as e:
            logging.error(f"Error determining network range: {e}")
            return "192.168.1.0/24"
            
    def scan_network(self, selected_iface=None):
        """Perform an initial scan of the network"""
        network_range = self.get_network_range(selected_iface)
        logging.info(f"Scanning network: {network_range} using interface: {selected_iface}")
        
        # Always perform an interface-less scan first to see if we get any results
        try:
            logging.info("Attempting interface-less network scan first")
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range), 
                         timeout=2, verbose=0)
            
            if ans:
                logging.info(f"Interface-less scan successful, found {len(ans)} devices")
                self._process_scan_results(ans)
                return True
            else:
                logging.info("Interface-less scan returned no results, trying with interface specification")
        except Exception as e:
            logging.warning(f"Interface-less scan failed: {e}")
            
        # If we're here, either the interface-less scan failed or returned no results
        # Now try with the specified interface if one was provided
        if selected_iface:
            try:
                iface_for_scapy = selected_iface
                
                # On Windows, try to extract GUID if in the format "Name (GUID)"
                if platform.system() == 'Windows' and isinstance(selected_iface, str):
                    if '(' in selected_iface and ')' in selected_iface:
                        guid = selected_iface.split('(')[1].split(')')[0].strip()
                        logging.info(f"Extracted GUID from interface name: {guid}")
                        iface_for_scapy = guid
                
                # Try a scan with the interface
                logging.info(f"Attempting scan with interface: {iface_for_scapy}")
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range), 
                            timeout=2, verbose=0, iface=iface_for_scapy)
                
                if ans:
                    logging.info(f"Interface scan successful, found {len(ans)} devices")
                    self._process_scan_results(ans)
                    return True
                else:
                    logging.warning(f"Interface scan with {iface_for_scapy} returned no results")
            except Exception as e:
                logging.error(f"Error during network scan on interface {selected_iface}: {e}")
        
        # If we got this far, try one more time with a broader network range
        try:
            broader_range = "192.168.0.0/16"  # Try a broader range as last resort
            logging.info(f"Attempting final scan with broader range: {broader_range}")
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=broader_range), 
                         timeout=3, verbose=0)
            
            if ans:
                logging.info(f"Broader range scan successful, found {len(ans)} devices")
                self._process_scan_results(ans)
                return True
            else:
                logging.warning("All scan attempts returned no results")
                return False
        except Exception as e:
            logging.error(f"Final scan attempt also failed: {e}")
            return False
    
    def _process_scan_results(self, ans):
        """Process ARP scan results and update mappings"""
        with self.lock:
            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc
                current_time = time.time()
                
                if ip not in self.ip_mac_mappings:
                    self.ip_mac_mappings[ip] = {
                        "mac": mac, 
                        "time": current_time, 
                        "count": 1,
                        "first_time": current_time
                    }
                else:
                    self.ip_mac_mappings[ip]["time"] = current_time
                    self.ip_mac_mappings[ip]["count"] += 1
                
                logging.info(f"Found: {ip} at {mac}")
        return True

    def process_packet(self, packet):
        """Process each ARP packet and check for suspicious behavior."""
        if packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc.lower()
            
            if not src_mac or src_mac == "00:00:00:00:00:00" or src_mac == "ff:ff:ff:ff:ff:ff": 
                return
            if not src_ip or src_ip == "0.0.0.0": 
                return
            
            with self.lock:
                # Increment total packet counter
                self.total_packets += 1
                
                current_time = time.time()
                alert_msg = None
                
                # Get our IP address dynamically
                try:
                    my_ip = None
                    # First try to get our IP from our own mappings
                    for ip, data in self.ip_mac_mappings.items():
                        # If we have an item with a MAC that matches ours from netifaces, use its IP
                        if '.' in ip and ip != '0.0.0.0':  # Ensure it's a valid IPv4
                            my_ip = ip
                            break
                            
                    # If that failed, try to get it from netifaces
                    if not my_ip:
                        iface = self.get_default_interface()
                        if iface:
                            addrs = netifaces.ifaddresses(iface)
                            if netifaces.AF_INET in addrs:
                                my_ip = addrs[netifaces.AF_INET][0]['addr']
                except Exception as e:
                    logging.error(f"Error getting local IP: {e}")
                    my_ip = None
                
                if my_ip and src_ip != my_ip:
                    if my_ip in self.ip_mac_mappings:
                        our_real_mac = self.ip_mac_mappings[my_ip]["mac"].lower()
                        
                        if src_mac == our_real_mac:
                            logging.warning(f"ARP SPOOF DETECTED: Our MAC ({src_mac}) is claiming to be IP {src_ip} instead of {my_ip}!")
                            
                            alert_msg = f"MAC Spoof! MAC {src_mac} (belongs to {my_ip}) is now claiming IP {src_ip}"
                            
                            suspicious_activity = {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "ip": src_ip,
                                "old_mac": f"MAC associated with {my_ip}",
                                "new_mac": src_mac,
                                "time_diff": "0.00s"
                            }
                            self.suspicious_activities.append(suspicious_activity)
                
                if not alert_msg:
                    if src_ip not in self.ip_mac_mappings:
                        self.ip_mac_mappings[src_ip] = {
                            "mac": src_mac,
                            "time": current_time,
                            "count": 1,
                            "first_time": current_time
                        }
                        logging.info(f"New IP-MAC mapping detected: {src_ip} -> {src_mac}")
                    else:
                        self.ip_mac_mappings[src_ip]["time"] = current_time
                        self.ip_mac_mappings[src_ip]["count"] += 1
                        
                        old_mac = self.ip_mac_mappings[src_ip]["mac"]
                        if old_mac.lower() != src_mac.lower():
                            # MAC address has changed, could be spoofing
                            first_time = self.ip_mac_mappings[src_ip]["first_time"]
                            time_diff = f"{current_time - first_time:.2f}s"
                            logging.warning(f"ARP SPOOF ALERT! IP: {src_ip} changed MAC from {old_mac} to {src_mac} after {time_diff}")
                            
                            suspicious_activity = {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "ip": src_ip,
                                "old_mac": old_mac,
                                "new_mac": src_mac,
                                "time_diff": time_diff
                            }
                            self.suspicious_activities.append(suspicious_activity)
                            
                            # Update the MAC address in our mappings
                            self.ip_mac_mappings[src_ip]["mac"] = src_mac
    
    def start_sniffing(self, interface=None):
        """Start sniffing ARP packets"""
        if not interface:
            interface = self.get_default_interface()

        if not interface:
            logging.error("No valid interface identifier found for sniffing")
            return False

        logging.info(f"Attempting to start ARP packet sniffing on interface: {interface}")
        self.running = True

        try:
            self.sniff_thread = threading.Thread(
                target=self._do_sniffing,
                args=(interface,)
            )
            self.sniff_thread.daemon = True
            self.sniff_thread.start()
            return True
        except Exception as e:
            logging.error(f"Error preparing sniffing thread for interface '{interface}': {e}")
            self.running = False
            try:
                logging.info("Trying fallback to interface-less sniffing")
                self.sniff_thread = threading.Thread(target=self._do_sniffing, args=(None,))
                self.sniff_thread.daemon = True
                self.sniff_thread.start()
                return True
            except Exception as e2:
                logging.error(f"Fallback sniffing setup also failed: {e2}")
                return False

    def _do_sniffing(self, interface=None):
        """Internal method to perform the actual ARP packet sniffing."""
        try:
            if interface:
                # On Windows, sometimes we need to sanitize the interface name
                if platform.system() == 'Windows' and interface.startswith('{') and interface.endswith('}'): 
                    logging.info(f"Using interface GUID format for Windows: {interface}")
                
                logging.info(f"Sniffing thread started on interface: {interface}")
                try:
                    sniff(prn=self.process_packet, 
                        filter="arp", 
                        store=0,
                        iface=interface,
                        stop_filter=lambda p: not self.running)
                except Exception as e:
                    if "not found" in str(e).lower() or "no such" in str(e).lower():
                        logging.error(f"Interface '{interface}' not found, trying without interface specification.")
                        self._do_sniffing(None)  # Try again without interface
                    else:
                        raise  # Re-raise if it's a different error
            else:
                logging.info(f"Sniffing thread started in interface-less fallback mode.")
                sniff(prn=self.process_packet, 
                    filter="arp", 
                    store=0,
                    stop_filter=lambda p: not self.running)
        except Exception as e:
            logging.error(f"Error in sniffing thread (interface: {interface}): {e}")
            if interface:
                # If we failed with a specific interface, try without one
                logging.info("Trying fallback to interface-less sniffing due to error...")
                try:
                    sniff(prn=self.process_packet, 
                        filter="arp", 
                        store=0,
                        stop_filter=lambda p: not self.running)
                except Exception as e2:
                    logging.error(f"Interface-less fallback sniffing also failed: {e2}")
        finally:
            logging.info("Sniffing thread exiting")

    def stop_sniffing(self):
        """Stop the packet sniffing process"""
        logging.info("Stopping ARP packet sniffing")
        self.running = False
        
        if hasattr(self, 'sniff_thread') and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2.0)
            
        return True
        
    def get_device_count(self):
        """Return the count of unique devices seen"""
        with self.lock:
            return len(self.ip_mac_mappings)
            
    def get_suspicious_count(self):
        """Return the count of suspicious activities"""
        with self.lock:
            return len(self.suspicious_activities)
            
    def get_ip_mac_mappings(self):
        """Return a copy of the current IP-MAC mappings"""
        with self.lock:
            return self.ip_mac_mappings.copy()
            
    def get_suspicious_activities(self):
        """Return a copy of the suspicious activities list"""
        with self.lock:
            return self.suspicious_activities.copy()
            
    def simulate_arp_spoof(self, target_ip, spoof_ip, interface_identifier=None, duration=10):
        """Simulate an ARP spoofing attack"""
        if not interface_identifier:
            interface_identifier = self.get_default_interface()

        logging.info(f"Starting ARP spoof simulation on interface '{interface_identifier}': telling {target_ip} that we are {spoof_ip} for {duration}s")
        self.stop_spoofing_event.clear()

        try:
            target_mac = "ff:ff:ff:ff:ff:ff"
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=1, verbose=0, iface=interface_identifier)
                if ans:
                    target_mac = ans[0][1].hwsrc
                    logging.info(f"Found target MAC: {target_mac} for {target_ip}")
            except Exception as e:
                logging.warning(f"Could not find target MAC for {target_ip}, using broadcast: {e}")

            my_mac = None
            with self.lock:
                for ip, data in self.ip_mac_mappings.items():
                    if '192.168.1' in ip:
                        my_mac = data['mac']
                        logging.info(f"Using MAC from known mapping (IP: {ip}): {my_mac}")
                        break

            if not my_mac:
                try:
                    mac_num = getnode()
                    my_mac = ':'.join(("%012X" % mac_num)[i:i+2] for i in range(0, 12, 2)).lower()
                    logging.info(f"Using MAC from getnode (fallback): {my_mac}")
                except Exception as e:
                    logging.error(f"Error getting source MAC: {e}")
                    my_mac = "00:11:22:33:44:55"

            ether = Ether(dst=target_mac, src=my_mac)
            arp = ARP(op="is-at", pdst=target_ip, psrc=spoof_ip, hwdst=target_mac, hwsrc=my_mac)
            packet = ether/arp
            logging.info(f"Crafted ARP packet: {packet.summary()}")

            logging.info(f"IMPORTANT - Packet is using MAC: {my_mac}")
            logging.info(f"IMPORTANT - Our host's MAC (from init): {self.ip_mac_mappings.get('192.168.1.4', {}).get('mac', 'Not found')}")

            def send_packets():
                start_time = time.time()
                count = 0
                while not self.stop_spoofing_event.is_set() and time.time() - start_time < duration:
                    try:
                        sendp(packet, iface=interface_identifier, verbose=0)
                        count += 1
                    except Exception as e:
                        logging.warning(f"Error sending packet: {e}")
                    time.sleep(0.5)
                logging.info(f"Sent {count} spoofed ARP packets on '{interface_identifier}'.")

            self.spoofing_thread = threading.Thread(target=send_packets, daemon=True)
            self.spoofing_thread.start()
            return True

        except Exception as e:
            logging.error(f"Error starting ARP spoof simulation: {e}")
            return False

    def export_data(self, filename):
        """Export detection data to the specified file."""
        try:
            with open(filename, 'w') as f:
                f.write("ARP Spoofing Detection Data Export\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 50 + "\n\n")

                f.write("DETECTED DEVICES\n")
                f.write("-" * 50 + "\n")
                f.write(f"{'IP Address':<15} {'MAC Address':<18} {'First Seen':<20} {'Last Seen':<20} {'Count':<8}\n")

                mappings = self.get_ip_mac_mappings()
                for ip, info in mappings.items():
                    first_seen_ts = info.get('first_time', info.get('time', 0))
                    last_seen_ts = info.get('time', 0)
                    first_seen = datetime.fromtimestamp(first_seen_ts).strftime('%Y-%m-%d %H:%M:%S') if first_seen_ts else "N/A"
                    last_seen = datetime.fromtimestamp(last_seen_ts).strftime('%Y-%m-%d %H:%M:%S') if last_seen_ts else "N/A"
                    f.write(f"{ip:<15} {info.get('mac', 'Unknown'):<18} {first_seen:<20} {last_seen:<20} {info.get('count', 0):<8}\n")

                f.write("\n\n")

                f.write("SUSPICIOUS ACTIVITIES\n")
                f.write("-" * 50 + "\n")
                f.write(f"{'Timestamp':<20} {'IP Address':<15} {'Old MAC/Context':<30} {'New MAC':<18} {'Time Diff':<10}\n")

                activities = self.get_suspicious_activities()
                for activity in activities:
                    f.write(f"{activity.get('timestamp', ''):<20} {activity.get('ip', ''):<15} {activity.get('old_mac', ''):<30} ")
                    f.write(f"{activity.get('new_mac', ''):<18} {activity.get('time_diff', ''):<10}\n")

            logging.info(f"Data successfully exported to {filename}")
            return True
        except Exception as e:
            logging.error(f"Error exporting data to {filename}: {e}")
            return False

    def get_total_packet_count(self):
        """Return the total number of ARP packets captured"""
        with self.lock:
            return self.total_packets

if __name__ == "__main__":
    print("ARP Spoofing Detection Tool - Console Mode")
    print("-----------------------------------------")

    detector = ARPSpoofDetector()

    print("Performing initial network scan...")
    if not detector.scan_network():
        print("Network scan failed. Exiting.")
        exit()

    print(f"Found {detector.get_device_count()} devices on the network")
    for ip, data in detector.get_ip_mac_mappings().items():
        print(f" - {ip} at {data['mac']}")

    interface = detector.get_default_interface()
    if not interface:
        print("Could not find default interface. Trying interface-less sniffing.")
    else:
        print(f"Starting ARP packet sniffing on interface: {interface}")

    if not detector.start_sniffing(interface):
        print("Failed to start sniffing. Exiting.")
        exit()

    print("Monitoring started. Press Ctrl+C to stop.")

    try:
        last_alert_count = 0
        while True:
            time.sleep(10)
            device_count = detector.get_device_count()
            suspicious_count = detector.get_suspicious_count()
            print(f"\rStatus: Monitoring {device_count} devices, {suspicious_count} suspicious activities detected.", end='')

            if suspicious_count > last_alert_count:
                print("\n--- New Suspicious Activity ---")
                activities = detector.get_suspicious_activities()
                for activity in activities[last_alert_count:]:
                    print(f"ALERT: {activity.get('timestamp', '')} - IP {activity.get('ip', '')} changed from '{activity.get('old_mac', '')}' to '{activity.get('new_mac', '')}' in {activity.get('time_diff', '')}")
                last_alert_count = suspicious_count
                print("-----------------------------")

    except KeyboardInterrupt:
        print("\nStopping ARP monitoring...")
        detector.stop_sniffing()
        print("ARP monitoring stopped.")

        export_filename = "console_arp_report.txt"
        print(f"Exporting data to {export_filename}...")
        if detector.export_data(export_filename):
            print("Export complete.")
        else:
            print("Export failed.")

        print("Exiting.")