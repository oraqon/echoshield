import socket
import struct
from datetime import datetime
import os

# Connection parameters
HOST = '162.33.236.188'
PORT = 29982

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# Create log file with timestamp
log_filename = f"logs/track_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
log_file = None

# Debug mode - set to True to see raw hex data
DEBUG_MODE = False

# Global packet counter
packet_count = 0
MAX_PACKETS = 50

def log_print(message, console=True, file=True):
    """Print to console and/or log file"""
    if console:
        print(message)
    if file and log_file:
        log_file.write(message + '\n')
        log_file.flush()

def decode_track_packet(data):
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
                    log_print(f"\n[DEBUG] Raw packet header (first 64 bytes):")
                    log_print(f"[DEBUG] {packet[:64].hex()}")
                    log_print(f"[DEBUG] Packet length: {len(packet)} bytes\n")
                    
                # Parse header according to spec
                offset = 0
                field_count = 0
                
                
                # Packet header
                packet_sync = b'<tracks>'  # Already consumed
                
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                n_bytes = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                version_major = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                version_minor = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                version_patch = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                reserved_00 = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                radar_id = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # Track message header fields
                packet_type = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                state = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # reserved_01 = struct.unpack('<6B', packet[offset:offset+6])[0]
                reserved_01 = packet[offset:offset+6].hex()
                offset += 6
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                lifetime = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                confidence_level = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                informed_track_update_count = struct.unpack('<I', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # reserved_02 = struct.unpack('<8B', packet[offset:offset+8])[0]
                reserved_02 = packet[offset:offset+8].hex()
                offset += 8
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                track_id = struct.unpack('<Q', packet[offset:offset+8])[0]
                offset += 8
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # UUIDs (16 bytes each)
                track_UUID = packet[offset:offset+16].hex()
                offset += 16
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                handoff_UUID = packet[offset:offset+16].hex()
                offset += 16
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                track_merge_UUID = packet[offset:offset+16].hex()
                offset += 16
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # Position and velocity estimates (3 floats each = 12 bytes)
                xyz_pos_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                xyz_vel_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                ecef_pos_est = struct.unpack('<ddd', packet[offset:offset+24])
                offset += 24
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                ecef_vel_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                enu_pos_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                enu_vel_est = struct.unpack('<fff', packet[offset:offset+12])
                offset += 12
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # RCS estimates
                rcs_est = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                rcs_est_std = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # Track metadata
                track_formation_source = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                track_cause_of_death = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                track_is_focused = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                reserved_03 = struct.unpack('<B', packet[offset:offset+1])[0]
                offset += 1
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # Timestamps (assuming uint64 - 8 bytes each)
                last_update_time = struct.unpack('<Q', packet[offset:offset+8])[0]
                offset += 8
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                last_assoc_time = struct.unpack('<Q', packet[offset:offset+8])[0]
                offset += 8
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                acquired_time = struct.unpack('<Q', packet[offset:offset+8])[0]
                offset += 8
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # AGL and probabilities
                agl_est = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                prob_aircraft = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                prob_bird = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                prob_clutter = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                prob_human = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                prob_uav_fixedwing = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                prob_uav_multirotor = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                prob_vehicle = struct.unpack('<f', packet[offset:offset+4])[0]
                offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # reserved_04 = struct.unpack('<I', packet[offset:offset+4])[0]
                reserved_04 = packet[offset:offset+32].hex()
                offset += 32
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # ECEF state covariance (36 floats = 144 bytes for 6x6 matrix)
                ecef_state_covariance = []
                for i in range(21):
                    ecef_state_covariance.append(struct.unpack('<f', packet[offset:offset+4])[0])
                    offset += 4
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # reserved_05 = struct.unpack('<I', packet[offset:offset+4])[0]
                reserved_05 = packet[offset:offset+132].hex()
                offset += 132
                
                log_print(f"number: {field_count}, offset: {offset + 8}")
                field_count += 1
                
                # Check if extended data exists
                if (offset < n_bytes):
                    # Counts
                    n_outstanding_track_beams = struct.unpack('<B', packet[offset:offset+1])[0]
                    offset += 1
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    n_outstanding_clf_beams = struct.unpack('<B', packet[offset:offset+1])[0]
                    offset += 1
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    n_assoc_meas_ids = struct.unpack('<B', packet[offset:offset+1])[0]
                    offset += 1
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    n_assoc_cookie_ids = struct.unpack('<B', packet[offset:offset+1])[0]
                    offset += 1
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    # Association statistics
                    assoc_meas_mean_adjusted_rcs = struct.unpack('<f', packet[offset:offset+4])[0]
                    offset += 4
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    assoc_meas_chi2 = []
                    for i in range(6):
                        assoc_meas_chi2.append(struct.unpack('<f', packet[offset:offset+4])[0])
                        offset += 4
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    # Variable length arrays - read based on counts
                    assoc_meas_ids = []
                    for i in range(6):
                        assoc_meas_ids.append(struct.unpack('<Q', packet[offset:offset+8])[0])
                        offset += 8
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    outstanding_clf_beams_ids = []
                    for i in range(2):
                        outstanding_clf_beams_ids.append(struct.unpack('<Q', packet[offset:offset+8])[0])
                        offset += 8
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    last_clf_beam_time = struct.unpack('<Q', packet[offset:offset+8])[0]
                    offset += 8
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    outstanding_track_beams_ids = []
                    for i in range(4):
                        outstanding_track_beams_ids.append(struct.unpack('<Q', packet[offset:offset+8])[0])
                        offset += 8
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    last_track_beam_time = struct.unpack('<q', packet[offset:offset+8])[0]
                    offset += 8 
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    assoc_cookie_ids = []
                    for i in range(2):
                        assoc_cookie_ids.append(struct.unpack('<Q', packet[offset:offset+8])[0])
                        offset += 8
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                    
                    # Reserved field at end
                    reserved_06 = packet[offset:offset+64].hex()
                    offset += 64
                    
                    log_print(f"number: {field_count}, offset: {offset + 8}")
                    field_count += 1
                
                # Print all fields
                log_print(f"\n{'='*80}")
                log_print(f"TRACK PACKET #{packet_count}")
                log_print(f"{'='*80}")
                log_print(f"packet_sync: <tracks>")
                log_print(f"n_bytes: {n_bytes}")
                log_print(f"version: {version_major}.{version_minor}.{version_patch}")
                log_print(f"reserved_00: 0x{reserved_00:02X}")
                log_print(f"radar_id: {radar_id}")
                log_print(f"packet_type: {packet_type}")
                log_print(f"state: {state}")
                log_print(f"reserved_01: 0x{reserved_01}")
                log_print(f"lifetime: {lifetime}")
                log_print(f"confidence_level: {confidence_level:.4f}")
                log_print(f"informed_track_update_count: {informed_track_update_count}")
                log_print(f"reserved_02: 0x{reserved_02}")
                log_print(f"id: {track_id}")
                log_print(f"track_UUID: {track_UUID}")
                log_print(f"handoff_UUID: {handoff_UUID}")
                log_print(f"track_merge_UUID: {track_merge_UUID}")
                log_print(f"xyz_pos_est: [{xyz_pos_est[0]:.3f}, {xyz_pos_est[1]:.3f}, {xyz_pos_est[2]:.3f}] m")
                log_print(f"xyz_vel_est: [{xyz_vel_est[0]:.3f}, {xyz_vel_est[1]:.3f}, {xyz_vel_est[2]:.3f}] m/s")
                log_print(f"ecef_pos_est: [{ecef_pos_est[0]:.3f}, {ecef_pos_est[1]:.3f}, {ecef_pos_est[2]:.3f}] m")
                log_print(f"ecef_vel_est: [{ecef_vel_est[0]:.3f}, {ecef_vel_est[1]:.3f}, {ecef_vel_est[2]:.3f}] m/s")
                log_print(f"enu_pos_est: [{enu_pos_est[0]:.3f}, {enu_pos_est[1]:.3f}, {enu_pos_est[2]:.3f}] m")
                log_print(f"enu_vel_est: [{enu_vel_est[0]:.3f}, {enu_vel_est[1]:.3f}, {enu_vel_est[2]:.3f}] m/s")
                log_print(f"rcs_est: {rcs_est:.4f} dBsm")
                log_print(f"rcs_est_std: {rcs_est_std:.4f}")
                log_print(f"track_formation_source: {track_formation_source}")
                # log_print(f"track_cause_of_death: {track_cause_of_death}")
                # log_print(f"track_is_focused: {track_is_focused}")
                # log_print(f"reserved_03: 0x{reserved_03:02X}")
                # log_print(f"last_update_time: {last_update_time}")
                # log_print(f"last_assoc_time: {last_assoc_time}")
                # log_print(f"acquired_time: {acquired_time}")
                # log_print(f"agl_est: {agl_est:.3f} m")
                # log_print(f"prob_aircraft: {prob_aircraft:.4f}")
                # log_print(f"prob_bird: {prob_bird:.4f}")
                # log_print(f"prob_clutter: {prob_clutter:.4f}")
                # log_print(f"prob_human: {prob_human:.4f}")
                # log_print(f"prob_uav_fixedwing: {prob_uav_fixedwing:.4f}")
                # log_print(f"prob_uav_multirotor: {prob_uav_multirotor:.4f}")
                # log_print(f"prob_vehicle: {prob_vehicle:.4f}")
                # log_print(f"reserved_04: 0x{reserved_04:08X}")
                # log_print(f"ecef_state_covariance: [6x6 matrix with {len(ecef_state_covariance)} elements]")
                # log_print(f"reserved_05: 0x{reserved_05:08X}")
                # log_print(f"n_outstanding_track_beams: {n_outstanding_track_beams}")
                # log_print(f"n_outstanding_clf_beams: {n_outstanding_clf_beams}")
                # log_print(f"n_assoc_meas_ids: {n_assoc_meas_ids}")
                # log_print(f"n_assoc_cookie_ids: {n_assoc_cookie_ids}")
                # log_print(f"assoc_meas_mean_adjusted_rcs: {assoc_meas_mean_adjusted_rcs:.4f}")
                # log_print(f"assoc_meas_chi2: {assoc_meas_chi2:.4f}")
                # log_print(f"assoc_meas_ids: {assoc_meas_ids}")
                # log_print(f"outstanding_clf_beams_ids: {outstanding_clf_beams_ids}")
                # log_print(f"last_clf_beam_time: {last_clf_beam_time}")
                # log_print(f"outstanding_track_beams_ids: {outstanding_track_beams_ids}")
                # log_print(f"last_track_beam_time: {last_track_beam_time}")
                # log_print(f"assoc_cookie_ids: {assoc_cookie_ids}")
                # log_print(f"reserved_06: {reserved_06[:40]}{'...' if len(reserved_06) > 40 else ''}")
                log_print(f"{'='*80}\n")
                
                if packet_count >= MAX_PACKETS:
                    return False
                
    except Exception as e:
        log_print(f"Error decoding packet: {e}")
        import traceback
        log_print(traceback.format_exc())
        # Fall back to hex dump
        log_print(f"Raw data (first 256 bytes): {data[:256].hex()}")
    
    return True

def connect_and_receive():
    global log_file
    buffer = b''
    
    try:
        # Open log file
        log_file = open(log_filename, 'w', encoding='utf-8')
        log_print(f"Track Data Log - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        log_print(f"Connecting to {HOST}:{PORT}...")
        log_print("="*60 + "\n")
        
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # 10 second timeout
        
        sock.connect((HOST, PORT))
        log_print("Connected successfully!")
        log_print("Receiving and decoding track data...\n")
        
        while True:
            data = sock.recv(4096)
            if not data:
                log_print("\nConnection closed by remote host.")
                break
            
            # Add to buffer
            buffer += data
            
            # Process complete packets
            while b'<tracks>' in buffer:
                # Find the start of next packet
                start_idx = buffer.find(b'<tracks>')
                
                # Look for the end or next packet
                next_start = buffer.find(b'<tracks>', start_idx + 8)
                
                if next_start == -1:
                    # Wait for more data
                    break
                
                # Extract complete packet
                packet = buffer[start_idx:next_start]
                buffer = buffer[next_start:]
                
                # Decode the packet
                should_continue = decode_track_packet(packet)
                if not should_continue:
                    log_print(f"\nReached maximum packet limit ({MAX_PACKETS}). Stopping.")
                    return
            
    except socket.timeout:
        log_print("Connection timed out.")
    except ConnectionRefusedError:
        log_print("Connection refused. The server may not be running.")
    except KeyboardInterrupt:
        log_print("\n\nInterrupted by user.")
    except Exception as e:
        log_print(f"Error: {e}")
    finally:
        sock.close()
        log_print(f"\nSocket closed.")
        log_print(f"Log ended at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if log_file:
            log_file.close()
            print(f"\nLog saved to: {log_filename}")

if __name__ == "__main__":
    connect_and_receive()
