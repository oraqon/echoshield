import socket
import struct
from datetime import datetime
import os
import threading
import signal
import sys

# Connection parameters
HOST = '162.33.236.188'
TRACK_PORT = 29982
STATUS_PORT = 29979
COMMAND_PORT = 29978

# Command message ID counter
command_id = 1

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# Create log files with timestamp
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
track_log_filename = f"logs/track_data_{timestamp}.log"
status_log_filename = f"logs/status_data_{timestamp}.log"
command_log_filename = f"logs/command_data_{timestamp}.log"
track_log_file = None
status_log_file = None
command_log_file = None

# Debug mode - set to True to see raw hex data
DEBUG_MODE = False

# Global packet counter
packet_count = 0
MAX_PACKETS = 500000

# Shutdown flag
shutdown_flag = threading.Event()

def log_print(message, console=True, file_handle=None):
    """Print to console and/or log file"""
    if console:
        print(message)
    if file_handle:
        file_handle.write(message + '\n')
        file_handle.flush()

def send_command(command_method):
    """Send a JSON command to the radar via the command port"""
    global command_id, command_log_file
    
    try:
        import json
        
        # Open command log file if not already open
        if command_log_file is None:
            command_log_file = open(command_log_filename, 'w', encoding='utf-8')
            log_print(f"Command Log - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", console=False, file_handle=command_log_file)
            log_print("="*60 + "\n", console=False, file_handle=command_log_file)
        
        # Create command message
        command = {
            "method": command_method,
            "id": command_id
        }
        command_id += 1
        
        # Convert to JSON string and encode
        command_json = json.dumps(command)
        command_bytes = command_json.encode('utf-8')
        
        # Log command being sent
        log_print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]", console=True, file_handle=command_log_file)
        log_print(f"Sending command: {command_json}", console=True, file_handle=command_log_file)
        
        # Connect and send command
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        
        log_print(f"Connecting to {HOST}:{COMMAND_PORT}...", console=True, file_handle=command_log_file)
        sock.connect((HOST, COMMAND_PORT))
        log_print(f"Connected successfully", console=True, file_handle=command_log_file)
        
        log_print(f"Sending {len(command_bytes)} bytes: {command_bytes}", console=True, file_handle=command_log_file)
        sock.sendall(command_bytes)
        log_print(f"Command sent successfully to {HOST}:{COMMAND_PORT}", console=True, file_handle=command_log_file)
        
        # Wait for response
        try:
            response = sock.recv(1024)
            if response:
                response_str = response.decode('utf-8', errors='ignore')
                log_print(f"Command response: {response_str}", console=True, file_handle=command_log_file)
                
                # Try to parse as JSON for pretty logging
                try:
                    response_json = json.loads(response_str)
                    log_print(f"Parsed response: {json.dumps(response_json, indent=2)}", console=True, file_handle=command_log_file)
                except:
                    pass
            else:
                log_print("No response received (empty)", console=True, file_handle=command_log_file)
        except socket.timeout:
            log_print("No response received (timeout)", console=True, file_handle=command_log_file)
        
        log_print("-"*60, console=False, file_handle=command_log_file)
        
        sock.close()
        return True
        
    except Exception as e:
        log_print(f"Error sending command: {e}", console=True, file_handle=command_log_file)
        return False

def decode_status_packet(data, file_handle):
    """
    Decode Gen3 Status Packet format based on Table 213 in specification
    """
    try:
        # Look for status packet delimiter
        if b'<status>' in data:
            packets = data.split(b'<status>')
            
            for packet in packets[1:]:
                if len(packet) < 20:
                    continue
                
                offset = 0
                
                # Packet header
                packet_sync = b'<status>'
                n_bytes = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                version_major = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                version_minor = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                version_patch = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # unit_serial - char[64]
                unit_serial = packet[offset:offset+64].decode('utf-8', errors='ignore').rstrip('\x00')
                offset += 64
                
                # system_health_status - uint8_t
                system_health_status = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # system_mode - char[64]
                system_mode = packet[offset:offset+64].decode('utf-8', errors='ignore').rstrip('\x00')
                offset += 64
                
                # fault_reason - char[128]
                fault_reason = packet[offset:offset+128].decode('utf-8', errors='ignore').rstrip('\x00')
                offset += 128
                
                # transmitter_output_power_control - uint32_t
                transmitter_output_power_control = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # radar_uptime - uint32_t
                radar_uptime = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # net_state_1g - uint32_t
                net_state_1g = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # link_status_10g - uint32_t
                link_status_10g = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # system_time - int64_t
                system_time = struct.unpack('<q', packet[offset:offset+8])[0]
                offset += 8
                
                # active_time_source - uint32_t
                active_time_source = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # available_time_sources - uint32_t
                available_time_sources = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # search_scan_rate - float
                search_scan_rate = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # kinematics_sensor_agreement - uint32_t
                kinematics_sensor_agreement = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # reserved_00 - uint8_t[1008]
                reserved_00 = packet[offset:offset+1008].hex()
                offset += 1008
                
                # Print status fields
                log_print(f"\n{'='*80}", console=True, file_handle=file_handle)
                log_print(f"STATUS PACKET", console=True, file_handle=file_handle)
                log_print(f"{'='*80}", console=True, file_handle=file_handle)
                log_print(f"packet_sync: <status>", console=True, file_handle=file_handle)
                log_print(f"n_bytes: {n_bytes}", console=True, file_handle=file_handle)
                log_print(f"version: {version_major}.{version_minor}.{version_patch}", console=True, file_handle=file_handle)
                log_print(f"unit_serial: {unit_serial}", console=True, file_handle=file_handle)
                log_print(f"system_health_status: {system_health_status}", console=True, file_handle=file_handle)
                log_print(f"system_mode: {system_mode}", console=True, file_handle=file_handle)
                log_print(f"fault_reason: {fault_reason}", console=True, file_handle=file_handle)
                log_print(f"transmitter_output_power_control: {transmitter_output_power_control}", console=True, file_handle=file_handle)
                log_print(f"radar_uptime: {radar_uptime} ms", console=True, file_handle=file_handle)
                log_print(f"net_state_1g: {net_state_1g}", console=True, file_handle=file_handle)
                log_print(f"link_status_10g: {link_status_10g}", console=True, file_handle=file_handle)
                log_print(f"system_time: {system_time}", console=True, file_handle=file_handle)
                log_print(f"active_time_source: {active_time_source}", console=True, file_handle=file_handle)
                log_print(f"available_time_sources: {available_time_sources}", console=True, file_handle=file_handle)
                log_print(f"search_scan_rate: {search_scan_rate:.4f}", console=True, file_handle=file_handle)
                log_print(f"kinematics_sensor_agreement: {kinematics_sensor_agreement}", console=True, file_handle=file_handle)
                log_print(f"reserved_00: 0x{reserved_00[:40]}{'...' if len(reserved_00) > 40 else ''}", console=True, file_handle=file_handle)
                
                log_print(f"{'='*80}\n", console=True, file_handle=file_handle)
                
    except Exception as e:
        log_print(f"Error decoding status packet: {e}", console=True, file_handle=file_handle)
        import traceback
        log_print(traceback.format_exc(), console=True, file_handle=file_handle)
        log_print(f"Raw data (first 256 bytes): {data[:256].hex()}", console=True, file_handle=file_handle)

def decode_track_packet(data, file_handle=None):
    """
    Decode Gen3 Track Packet format based on specification page 203
    Returns True if should continue, False if limit reached
    """
    global packet_count
    
    try:
        # Look for track packet delimiter
        if b'<tracks>' in data:
            # Find all track packet boundaries
            packets = data.split(b'<tracks>')
            
            for packet in packets[1:]:  # Skip first empty split
                if len(packet) < 20:  # Minimum header size
                    continue
                
                packet_count += 1
                if packet_count > MAX_PACKETS:  # Stop after max packets
                    return False
                
                # Show raw header bytes in debug mode
                if DEBUG_MODE:
                    log_print(f"\n[DEBUG] Raw packet header (first 64 bytes):", console=True, file_handle=file_handle)
                    log_print(f"[DEBUG] {packet[:64].hex()}", console=True, file_handle=file_handle)
                    log_print(f"[DEBUG] Packet length: {len(packet)} bytes\n", console=True, file_handle=file_handle)
                    
                # Parse header according to spec
                offset = 0
                field_count = 0
                
                
                # Packet header
                packet_sync = b'<tracks>'  # Already consumed
                
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                n_bytes = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                version_major = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                version_minor = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                version_patch = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                reserved_00 = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                radar_id = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # Track message header fields
                packet_type = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                state = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # reserved_01 = struct.unpack('<6B', packet[offset:offset+6])[0]
                reserved_01 = packet[offset:offset+6].hex()
                offset += 6
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                lifetime = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                confidence_level = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                informed_track_update_count = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # reserved_02 = struct.unpack('<8B', packet[offset:offset+8])[0]
                reserved_02 = packet[offset:offset+8].hex()
                offset += 8
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                track_id = struct.unpack('<Q', packet[offset:offset+8])[0]
                offset += 8
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # UUIDs (16 bytes each)
                track_UUID = packet[offset:offset+16].hex()
                offset += 16
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                handoff_UUID = packet[offset:offset+16].hex()
                offset += 16
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                track_merge_UUID = packet[offset:offset+16].hex()
                offset += 16
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # Position and velocity estimates (3 floats each = 12 bytes)
                xyz_pos_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                xyz_vel_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                ecef_pos_est = struct.unpack('<ddd', packet[offset:offset+24])
                offset += 24
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                ecef_vel_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                enu_pos_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                enu_vel_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # RCS estimates
                rcs_est = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                rcs_est_std = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # Track metadata
                track_formation_source = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                track_cause_of_death = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                track_is_focused = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                reserved_03 = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # Timestamps (assuming uint64 - 8 bytes each)
                last_update_time = struct.unpack('<Q', packet[offset:offset+8])[0]
                offset += 8
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                last_assoc_time = struct.unpack('<Q', packet[offset:offset+8])[0]
                offset += 8
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                acquired_time = struct.unpack('<Q', packet[offset:offset+8])[0]
                offset += 8
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # AGL and probabilities
                agl_est = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                prob_aircraft = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                prob_bird = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                prob_clutter = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                prob_human = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                prob_uav_fixedwing = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                prob_uav_multirotor = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                prob_vehicle = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # reserved_04 = struct.unpack('<I', packet[offset:offset+4])[0]
                reserved_04 = packet[offset:offset+32].hex()
                offset += 32
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # ECEF state covariance (36 floats = 144 bytes for 6x6 matrix)
                ecef_state_covariance = []
                for i in range(21):
                    ecef_state_covariance.append(struct.unpack('<f', packet[offset:offset+4])[0])
                    offset += 4
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # reserved_05 = struct.unpack('<I', packet[offset:offset+4])[0]
                reserved_05 = packet[offset:offset+132].hex()
                offset += 132
                
                # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                # field_count += 1
                
                # Check if extended data exists
                if (offset < n_bytes):
                    # Counts
                    n_outstanding_track_beams = struct.unpack('<B', packet[offset:offset+1])[0]
                    offset += 1
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    n_outstanding_clf_beams = struct.unpack('<B', packet[offset:offset+1])[0]
                    offset += 1
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    n_assoc_meas_ids = struct.unpack('<B', packet[offset:offset+1])[0]
                    offset += 1
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    n_assoc_cookie_ids = struct.unpack('<B', packet[offset:offset+1])[0]
                    offset += 1
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    # Association statistics
                    assoc_meas_mean_adjusted_rcs = struct.unpack('<f', packet[offset:offset+4])[0]
                    offset += 4
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    assoc_meas_chi2 = []
                    for i in range(6):
                        assoc_meas_chi2.append(struct.unpack('<f', packet[offset:offset+4])[0])
                        offset += 4
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    # Variable length arrays - read based on counts
                    assoc_meas_ids = []
                    for i in range(6):
                        assoc_meas_ids.append(struct.unpack('<Q', packet[offset:offset+8])[0])
                        offset += 8
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    outstanding_clf_beams_ids = []
                    for i in range(2):
                        outstanding_clf_beams_ids.append(struct.unpack('<Q', packet[offset:offset+8])[0])
                        offset += 8
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    last_clf_beam_time = struct.unpack('<Q', packet[offset:offset+8])[0]
                    offset += 8
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    outstanding_track_beams_ids = []
                    for i in range(4):
                        outstanding_track_beams_ids.append(struct.unpack('<Q', packet[offset:offset+8])[0])
                        offset += 8
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    last_track_beam_time = struct.unpack('<q', packet[offset:offset+8])[0]
                    offset += 8 
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    assoc_cookie_ids = []
                    for i in range(2):
                        assoc_cookie_ids.append(struct.unpack('<Q', packet[offset:offset+8])[0])
                        offset += 8
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                    
                    # Reserved field at end
                    reserved_06 = packet[offset:offset+64].hex()
                    offset += 64
                    
                    # log_print(f"number: {field_count}, offset: {offset + 8}", console=True, file_handle=file_handle)
                    # field_count += 1
                
                # Print all fields
                log_print(f"\n{'='*80}", console=True, file_handle=file_handle)
                log_print(f"TRACK PACKET #{packet_count}", console=True, file_handle=file_handle)
                log_print(f"{'='*80}", console=True, file_handle=file_handle)
                log_print(f"packet_sync: <tracks>", console=True, file_handle=file_handle)
                log_print(f"n_bytes: {n_bytes}", console=True, file_handle=file_handle)
                log_print(f"version: {version_major}.{version_minor}.{version_patch}", console=True, file_handle=file_handle)
                log_print(f"reserved_00: 0x{reserved_00:02X}", console=True, file_handle=file_handle)
                log_print(f"radar_id: {radar_id}", console=True, file_handle=file_handle)
                log_print(f"packet_type: {packet_type}", console=True, file_handle=file_handle)
                log_print(f"state: {state}", console=True, file_handle=file_handle)
                log_print(f"reserved_01: 0x{reserved_01}", console=True, file_handle=file_handle)
                log_print(f"lifetime: {lifetime}", console=True, file_handle=file_handle)
                log_print(f"confidence_level: {confidence_level:.4f}", console=True, file_handle=file_handle)
                log_print(f"informed_track_update_count: {informed_track_update_count}", console=True, file_handle=file_handle)
                log_print(f"reserved_02: 0x{reserved_02}", console=True, file_handle=file_handle)
                log_print(f"id: {track_id}", console=True, file_handle=file_handle)
                log_print(f"track_UUID: {track_UUID}", console=True, file_handle=file_handle)
                log_print(f"handoff_UUID: {handoff_UUID}", console=True, file_handle=file_handle)
                log_print(f"track_merge_UUID: {track_merge_UUID}", console=True, file_handle=file_handle)
                log_print(f"xyz_pos_est: [{xyz_pos_est[0]:.3f}, {xyz_pos_est[1]:.3f}, {xyz_pos_est[2]:.3f}] m", console=True, file_handle=file_handle)
                log_print(f"xyz_vel_est: [{xyz_vel_est[0]:.3f}, {xyz_vel_est[1]:.3f}, {xyz_vel_est[2]:.3f}] m/s", console=True, file_handle=file_handle)
                log_print(f"ecef_pos_est: [{ecef_pos_est[0]:.3f}, {ecef_pos_est[1]:.3f}, {ecef_pos_est[2]:.3f}] m", console=True, file_handle=file_handle)
                log_print(f"ecef_vel_est: [{ecef_vel_est[0]:.3f}, {ecef_vel_est[1]:.3f}, {ecef_vel_est[2]:.3f}] m/s", console=True, file_handle=file_handle)
                log_print(f"enu_pos_est: [{enu_pos_est[0]:.3f}, {enu_pos_est[1]:.3f}, {enu_pos_est[2]:.3f}] m", console=True, file_handle=file_handle)
                log_print(f"enu_vel_est: [{enu_vel_est[0]:.3f}, {enu_vel_est[1]:.3f}, {enu_vel_est[2]:.3f}] m/s", console=True, file_handle=file_handle)
                log_print(f"rcs_est: {rcs_est:.4f} dBsm", console=True, file_handle=file_handle)
                log_print(f"rcs_est_std: {rcs_est_std:.4f}", console=True, file_handle=file_handle)
                log_print(f"track_formation_source: {track_formation_source}", console=True, file_handle=file_handle)
                log_print(f"track_cause_of_death: {track_cause_of_death}", console=True, file_handle=file_handle)
                log_print(f"track_is_focused: {track_is_focused}", console=True, file_handle=file_handle)
                log_print(f"reserved_03: 0x{reserved_03:02X}", console=True, file_handle=file_handle)
                log_print(f"last_update_time: {last_update_time}", console=True, file_handle=file_handle)
                log_print(f"last_assoc_time: {last_assoc_time}", console=True, file_handle=file_handle)
                log_print(f"acquired_time: {acquired_time}", console=True, file_handle=file_handle)
                log_print(f"agl_est: {agl_est:.3f} m", console=True, file_handle=file_handle)
                log_print(f"prob_aircraft: {prob_aircraft:.4f}", console=True, file_handle=file_handle)
                log_print(f"prob_bird: {prob_bird:.4f}", console=True, file_handle=file_handle)
                log_print(f"prob_clutter: {prob_clutter:.4f}", console=True, file_handle=file_handle)
                log_print(f"prob_human: {prob_human:.4f}", console=True, file_handle=file_handle)
                log_print(f"prob_uav_fixedwing: {prob_uav_fixedwing:.4f}", console=True, file_handle=file_handle)
                log_print(f"prob_uav_multirotor: {prob_uav_multirotor:.4f}", console=True, file_handle=file_handle)
                log_print(f"prob_vehicle: {prob_vehicle:.4f}", console=True, file_handle=file_handle)
                log_print(f"reserved_04: 0x{reserved_04}", console=True, file_handle=file_handle)

                log_print(f"ecef_state_covariance: [6x6 matrix with {len(ecef_state_covariance)} elements]", console=True, file_handle=file_handle)
                log_print(f"reserved_05: 0x{reserved_05}", console=True, file_handle=file_handle)
                
                if (offset < n_bytes):
                    log_print(f"n_outstanding_track_beams: {n_outstanding_track_beams}", console=True, file_handle=file_handle)
                    log_print(f"n_outstanding_clf_beams: {n_outstanding_clf_beams}", console=True, file_handle=file_handle)
                    log_print(f"n_assoc_meas_ids: {n_assoc_meas_ids}", console=True, file_handle=file_handle)
                    log_print(f"n_assoc_cookie_ids: {n_assoc_cookie_ids}", console=True, file_handle=file_handle)
                    log_print(f"assoc_meas_mean_adjusted_rcs: {assoc_meas_mean_adjusted_rcs:.4f}", console=True, file_handle=file_handle)
                    log_print(
                        "assoc_meas_chi2: " + ", ".join(f"{v:.4f}" for v in assoc_meas_chi2),
                        console=True,
                        file_handle=file_handle
                    )
                    log_print(f"assoc_meas_ids: {assoc_meas_ids}", console=True, file_handle=file_handle)
                    log_print(f"outstanding_clf_beams_ids: {outstanding_clf_beams_ids}", console=True, file_handle=file_handle)
                    log_print(f"last_clf_beam_time: {last_clf_beam_time}", console=True, file_handle=file_handle)
                    log_print(f"outstanding_track_beams_ids: {outstanding_track_beams_ids}", console=True, file_handle=file_handle)
                    log_print(f"last_track_beam_time: {last_track_beam_time}", console=True, file_handle=file_handle)
                    log_print(f"assoc_cookie_ids: {assoc_cookie_ids}", console=True, file_handle=file_handle)
                    log_print(f"reserved_06: {reserved_06[:40]}{'...' if len(reserved_06) > 40 else ''}", console=True, file_handle=file_handle)
                
                # log_print(f"reserved_06: {reserved_06[:40]}{'...' if len(reserved_06) > 40 else ''}")
                log_print(f"{'='*80}\n", console=True, file_handle=file_handle)
                
                if packet_count >= MAX_PACKETS:
                    return False
                
    except Exception as e:
        log_print(f"Error decoding packet: {e}", console=True, file_handle=file_handle)
        import traceback
        log_print(traceback.format_exc(), console=True, file_handle=file_handle)
        # Fall back to hex dump
        log_print(f"Raw data (first 256 bytes): {data[:256].hex()}", console=True, file_handle=file_handle)
    
    return True

def connect_and_receive():
    global track_log_file, status_log_file
    
    # Monitor status and keep sending mode_set_start until ACTIVE
    print("Monitoring radar status and sending mode_set_start commands...")
    import time
    
    # Create a flag to track if we should keep sending commands
    keep_sending = threading.Event()
    keep_sending.set()
    
    def command_sender():
        """Thread to continuously send mode_set_start when radar is IDLE"""
        while keep_sending.is_set() and not shutdown_flag.is_set():
            send_command("mode_set_start")
            time.sleep(5)  # Wait 5 seconds between commands
    
    def status_monitor():
        """Thread to monitor status and stop commands when ACTIVE"""
        global status_log_file
        buffer = b''
        
        try:
            status_log_file = open(status_log_filename, 'w', encoding='utf-8')
            log_print(f"Status Data Log - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", console=True, file_handle=status_log_file)
            log_print(f"Connecting to {HOST}:{STATUS_PORT}...", console=True, file_handle=status_log_file)
            log_print("="*60 + "\n", console=True, file_handle=status_log_file)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30.0)
            sock.connect((HOST, STATUS_PORT))
            
            log_print("Status connection successful!", console=True, file_handle=status_log_file)
            log_print("Receiving and decoding status data...\n", console=True, file_handle=status_log_file)
            
            while not shutdown_flag.is_set():
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                    
                if not data:
                    log_print("\nStatus connection closed by remote host.", console=True, file_handle=status_log_file)
                    break
                
                buffer += data
                
                # Check if radar is ACTIVE
                if b'Operation:ACTIVE' in data:
                    print("\n*** Radar is now ACTIVE! Stopping mode_set_start commands. ***\n")
                    keep_sending.clear()  # Stop sending commands
                elif b'Operation:IDLE' in data:
                    if not keep_sending.is_set():
                        print("\n*** Radar back to IDLE! Resuming mode_set_start commands. ***\n")
                        keep_sending.set()  # Resume sending commands
                
                while b'<status>' in buffer:
                    start_idx = buffer.find(b'<status>')
                    next_start = buffer.find(b'<status>', start_idx + 8)
                    
                    if next_start == -1:
                        break
                    
                    packet = buffer[start_idx:next_start]
                    buffer = buffer[next_start:]
                    
                    decode_status_packet(packet, status_log_file)
                        
        except socket.timeout:
            log_print("Status connection timed out.", console=True, file_handle=status_log_file)
        except ConnectionRefusedError:
            log_print("Status connection refused.", console=True, file_handle=status_log_file)
        except KeyboardInterrupt:
            log_print("\nStatus connection interrupted by user.", console=True, file_handle=status_log_file)
        except Exception as e:
            log_print(f"Status error: {e}", console=True, file_handle=status_log_file)
        finally:
            try:
                sock.close()
            except:
                pass
            log_print(f"\nStatus socket closed.", console=True, file_handle=status_log_file)
            log_print(f"Log ended at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", console=True, file_handle=status_log_file)
            if status_log_file:
                status_log_file.close()
                print(f"\nStatus log saved to: {status_log_filename}")
    
    print()
    
    def receive_track_data():
        """Thread function to receive track packets"""
        global track_log_file, packet_count
        buffer = b''
        
        try:
            track_log_file = open(track_log_filename, 'w', encoding='utf-8')
            log_print(f"Track Data Log - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", console=True, file_handle=track_log_file)
            log_print(f"Connecting to {HOST}:{TRACK_PORT}...", console=True, file_handle=track_log_file)
            log_print("="*60 + "\n", console=True, file_handle=track_log_file)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30.0)  # 30 second timeout
            sock.connect((HOST, TRACK_PORT))
            
            log_print("Track connection successful!", console=True, file_handle=track_log_file)
            log_print("Receiving and decoding track data...\n", console=True, file_handle=track_log_file)
            
            while not shutdown_flag.is_set():
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                
                if not data:
                    log_print("\nTrack connection closed by remote host.", console=True, file_handle=track_log_file)
                    break
                
                buffer += data
                
                while b'<tracks>' in buffer:
                    start_idx = buffer.find(b'<tracks>')
                    next_start = buffer.find(b'<tracks>', start_idx + 8)
                    
                    if next_start == -1:
                        break
                    
                    packet = buffer[start_idx:next_start]
                    buffer = buffer[next_start:]
                    
                    should_continue = decode_track_packet(packet, track_log_file)
                    if not should_continue:
                        log_print(f"\nReached maximum packet limit ({MAX_PACKETS}). Stopping.", console=True, file_handle=track_log_file)
                        shutdown_flag.set()
                        sock.close()
                        return
                        
        except socket.timeout:
            log_print("Track connection timed out.", console=True, file_handle=track_log_file)
        except ConnectionRefusedError:
            log_print("Track connection refused.", console=True, file_handle=track_log_file)
        except KeyboardInterrupt:
            log_print("\nTrack connection interrupted by user.", console=True, file_handle=track_log_file)
        except Exception as e:
            log_print(f"Track error: {e}", console=True, file_handle=track_log_file)
        finally:
            try:
                sock.close()
            except:
                pass
            log_print(f"\nTrack socket closed.", console=True, file_handle=track_log_file)
            log_print(f"Log ended at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", console=True, file_handle=track_log_file)
            if track_log_file:
                track_log_file.close()
                print(f"\nTrack log saved to: {track_log_filename}")
    
    # Create and start threads
    command_thread = threading.Thread(target=command_sender, daemon=True)
    status_thread = threading.Thread(target=status_monitor, daemon=True)
    track_thread = threading.Thread(target=receive_track_data, daemon=True)
    
    # Signal handler for Ctrl+C
    def signal_handler(sig, frame):
        print("\n\nInterrupted by user. Shutting down...")
        shutdown_flag.set()
        keep_sending.clear()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start command sender first
    command_thread.start()
    time.sleep(1)  # Give it a moment to send first command
    
    # Then start monitoring threads
    status_thread.start()
    track_thread.start()
    
    # Wait for threads to complete or shutdown signal
    try:
        while command_thread.is_alive() or status_thread.is_alive() or track_thread.is_alive():
            command_thread.join(timeout=0.5)
            status_thread.join(timeout=0.5)
            track_thread.join(timeout=0.5)
            if shutdown_flag.is_set():
                break
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Shutting down...")
        shutdown_flag.set()
        keep_sending.clear()

if __name__ == "__main__":
    connect_and_receive()
