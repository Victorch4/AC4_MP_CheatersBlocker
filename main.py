import sys
import os
import configparser
import math
import requests
import subprocess
import ctypes
import ipaddress
import tempfile
import atexit
from ctypes import wintypes
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtMultimedia import QSoundEffect

# Resource path function for PyInstaller compatibility
def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    
    return os.path.join(base_path, relative_path)

# Windows API constants and functions for global hotkeys
VK_F1 = 0x70
VK_F2 = 0x71
VK_F3 = 0x72

# Import Windows API functions
user32 = ctypes.windll.user32

# Define structures and functions
class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ('vkCode', wintypes.DWORD),
        ('scanCode', wintypes.DWORD),
        ('flags', wintypes.DWORD),
        ('time', wintypes.DWORD),
        ('dwExtraInfo', ctypes.POINTER(wintypes.ULONG))
    ]

# Types for callback functions
HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(KBDLLHOOKSTRUCT))

# Windows API functions
SetWindowsHookEx = user32.SetWindowsHookExW
SetWindowsHookEx.argtypes = [ctypes.c_int, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]
SetWindowsHookEx.restype = wintypes.HHOOK

CallNextHookEx = user32.CallNextHookEx
CallNextHookEx.argtypes = [wintypes.HHOOK, ctypes.c_int, ctypes.c_int, ctypes.POINTER(KBDLLHOOKSTRUCT)]
CallNextHookEx.restype = ctypes.c_int

UnhookWindowsHookEx = user32.UnhookWindowsHookEx
UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
UnhookWindowsHookEx.restype = ctypes.c_bool

GetMessage = user32.GetMessageW
GetMessage.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, ctypes.c_uint, ctypes.c_uint]
GetMessage.restype = ctypes.c_int

TranslateMessage = user32.TranslateMessage
DispatchMessage = user32.DispatchMessageW

PostThreadMessage = user32.PostThreadMessageW
PostThreadMessage.argtypes = [wintypes.DWORD, ctypes.c_uint, wintypes.WPARAM, wintypes.LPARAM]
PostThreadMessage.restype = ctypes.c_bool

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100


class HotkeyManager(QThread):
    """Manager for handling global hotkeys"""
    
    hotkey_signal = pyqtSignal(int)
    
    def __init__(self):
        super().__init__()
        self.hook_id = None
        self.running = False
        
    def run(self):
        """Starts the hotkey processing loop"""
        self.running = True
        
        # Set low-level keyboard hook
        self.hook_proc = HOOKPROC(self.keyboard_hook)
        self.hook_id = SetWindowsHookEx(WH_KEYBOARD_LL, self.hook_proc, None, 0)
        
        if not self.hook_id:
            print("Failed to set keyboard hook")
            return
        
        # Start message loop
        msg = wintypes.MSG()
        while self.running and GetMessage(ctypes.byref(msg), None, 0, 0):
            TranslateMessage(ctypes.byref(msg))
            DispatchMessage(ctypes.byref(msg))
        
        # Remove hook on exit
        if self.hook_id:
            UnhookWindowsHookEx(self.hook_id)
    
    def keyboard_hook(self, n_code, w_param, l_param):
        """Key press handler"""
        if n_code >= 0:
            # Get information about pressed key
            kbd_struct = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            
            # Check for F1, F2, F3 presses
            if w_param == WM_KEYDOWN:
                if kbd_struct.vkCode == VK_F1:
                    self.hotkey_signal.emit(1)
                elif kbd_struct.vkCode == VK_F2:
                    self.hotkey_signal.emit(2)
                elif kbd_struct.vkCode == VK_F3:
                    self.hotkey_signal.emit(3)
        
        # Pass event further down the chain
        return CallNextHookEx(self.hook_id, n_code, w_param, l_param)
    
    def stop(self):
        """Stops the hotkey handler"""
        self.running = False
        
        # Send message to exit GetMessage loop immediately
        try:
            # Use PostQuitMessage instead of PostThreadMessage for faster exit
            user32.PostQuitMessage(0)
        except:
            pass


class FirewallRuleManager:
    """Manager for working with Windows Firewall rules"""
    
    def __init__(self):
        pass  # No rules tracking needed as we use INI file
    
    def create_rule(self, ip_range, direction='both'):
        """Creates a firewall rule for IP or IP range"""
        # Check if it's a range
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Create rule name for range
            rule_base_name = f"IPBlocker_RANGE_{start_ip.replace('.', '_')}_to_{end_ip.replace('.', '_')}"
            
            if direction in ['in', 'both']:
                rule_name = f"{rule_base_name}_IN"
                self._execute_rule_command_range('add', rule_name, start_ip, end_ip, 'in')
            
            if direction in ['out', 'both']:
                rule_name = f"{rule_base_name}_OUT"
                self._execute_rule_command_range('add', rule_name, start_ip, end_ip, 'out')
        else:
            # Single IP
            rule_base_name = f"IPBlocker_{ip_range.replace('.', '_')}"
            
            if direction in ['in', 'both']:
                rule_name = f"{rule_base_name}_IN"
                self._execute_rule_command('add', rule_name, ip_range, 'in')
            
            if direction in ['out', 'both']:
                rule_name = f"{rule_base_name}_OUT"
                self._execute_rule_command('add', rule_name, ip_range, 'out')
    
    def delete_rule(self, ip_range, direction='both'):
        """Deletes a firewall rule for IP or IP range"""
        # Check if it's a range
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Create rule name for range
            rule_base_name = f"IPBlocker_RANGE_{start_ip.replace('.', '_')}_to_{end_ip.replace('.', '_')}"
            
            if direction in ['in', 'both']:
                rule_name = f"{rule_base_name}_IN"
                self._execute_rule_command_range('delete', rule_name, start_ip, end_ip, 'in')
            
            if direction in ['out', 'both']:
                rule_name = f"{rule_base_name}_OUT"
                self._execute_rule_command_range('delete', rule_name, start_ip, end_ip, 'out')
        else:
            # Single IP
            rule_base_name = f"IPBlocker_{ip_range.replace('.', '_')}"
            
            if direction in ['in', 'both']:
                rule_name = f"{rule_base_name}_IN"
                self._execute_rule_command('delete', rule_name, ip_range, 'in')
            
            if direction in ['out', 'both']:
                rule_name = f"{rule_base_name}_OUT"
                self._execute_rule_command('delete', rule_name, ip_range, 'out')
    
    def _execute_rule_command(self, action, rule_name, ip_address, direction):
        """Executes netsh command for single IP rule operations"""
        dir_param = 'in' if direction == 'in' else 'out'
        
        try:
            if action == 'add':
                # Use CREATE_ALWAYS flag to avoid duplicates
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}',
                    f'dir={dir_param}',
                    'action=block',
                    f'remoteip={ip_address}',
                    'protocol=any'
                ], shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            elif action == 'delete':
                # Use timeout to prevent hanging
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}'
                ], shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=2)
        except subprocess.CalledProcessError as e:
            # Don't print error for missing rules
            if action == 'delete' and 'No rules match the specified criteria' not in str(e):
                print(f"Error executing {action} command for {rule_name}: {e}")
        except subprocess.TimeoutExpired:
            # Force terminate if hanging
            print(f"Timeout executing {action} command for {rule_name}")
        except Exception as e:
            # Silent fail for other exceptions
            pass
    
    def _execute_rule_command_range(self, action, rule_name, start_ip, end_ip, direction):
        """Executes netsh command for IP range rule operations"""
        dir_param = 'in' if direction == 'in' else 'out'
        
        try:
            if action == 'add':
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}',
                    f'dir={dir_param}',
                    'action=block',
                    f'remoteip={start_ip}-{end_ip}',
                    'protocol=any'
                ], shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            elif action == 'delete':
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}'
                ], shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=2)
        except subprocess.CalledProcessError as e:
            # Don't print error for missing rules
            if action == 'delete' and 'No rules match the specified criteria' not in str(e):
                print(f"Error executing {action} command for {rule_name}: {e}")
        except subprocess.TimeoutExpired:
            # Force terminate if hanging
            print(f"Timeout executing {action} command for {rule_name}")
        except Exception as e:
            # Silent fail for other exceptions
            pass
    
    def delete_specific_rule(self, rule_name):
        """Deletes a specific firewall rule by name"""
        try:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}'
            ], shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=2)
        except subprocess.CalledProcessError as e:
            # Don't print error for missing rules
            if 'No rules match the specified criteria' not in str(e):
                print(f"Error deleting rule {rule_name}: {e}")
        except subprocess.TimeoutExpired:
            print(f"Timeout deleting rule {rule_name}")
        except Exception as e:
            pass


class IPAddressManager:
    """Manager for loading and managing IP addresses"""
    
    def __init__(self):
        self.ip_addresses = []
        self.ip_ranges = []
    
    def load_from_url(self, url):
        """Loads IP addresses and ranges from specified URL"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Extract IP addresses and ranges
            lines = response.text.strip().split('\n')
            self.ip_addresses = []
            self.ip_ranges = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Check if it's a range
                if '-' in line:
                    if self._is_valid_ip_range(line):
                        self.ip_ranges.append(line)
                    else:
                        print(f"Invalid IP range format: {line}")
                # Check if it's a single IP
                elif self._is_valid_ip(line):
                    self.ip_addresses.append(line)
                else:
                    print(f"Invalid IP format: {line}")
            
            return True, self.ip_addresses + self.ip_ranges
        except requests.RequestException as e:
            return False, f"Loading error: {e}"
        except Exception as e:
            return False, f"Unexpected error: {e}"
    
    def _is_valid_ip(self, ip):
        """Validates single IP address"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False
    
    def _is_valid_ip_range(self, ip_range):
        """Validates IP range format XXX.XXX.XXX.XXX-XXX.XXX.XXX.XXX"""
        try:
            if '-' not in ip_range:
                return False
            
            start_ip, end_ip = ip_range.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Validate both IPs
            if not self._is_valid_ip(start_ip) or not self._is_valid_ip(end_ip):
                return False
            
            # Check if start IP is less than or equal to end IP
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            if start > end:
                return False
            
            return True
        except:
            return False
    
    def get_ips(self):
        """Returns list of all loaded IP addresses and ranges"""
        return self.ip_addresses + self.ip_ranges
    
    def is_range(self, ip_entry):
        """Checks if entry is an IP range"""
        return '-' in ip_entry
    
    def get_range_ips(self, ip_range):
        """Returns list of all IPs in a range (for display purposes)"""
        if not self.is_range(ip_range):
            return [ip_range]
        
        try:
            start_ip, end_ip = ip_range.split('-')
            start = ipaddress.IPv4Address(start_ip.strip())
            end = ipaddress.IPv4Address(end_ip.strip())
            
            ips = []
            # Limit to reasonable number for display
            total_ips = int(end) - int(start) + 1
            if total_ips <= 100:  # Only generate if range is small
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1
            
            return ips
        except:
            return [ip_range]


class ToggleButton(QPushButton):
    """Custom toggle button with two states"""
    
    def __init__(self, text_on, text_off, parent=None):
        super().__init__(text_off, parent)
        self.text_on = text_on
        self.text_off = text_off
        self.is_on = False
        self.clicked.connect(self.on_click)
        self.update_appearance()
    
    def on_click(self):
        """Handler for button click - doesn't toggle automatically"""
        # Don't toggle here, let the main logic handle it
        pass
    
    def set_state(self, state):
        """Sets button state based on actual status"""
        self.is_on = state
        self.update_appearance()
    
    def get_state(self):
        """Returns current button state"""
        return self.is_on
    
    def update_appearance(self):
        """Updates button appearance"""
        if self.is_on:
            self.setText(self.text_on)
        else:
            self.setText(self.text_off)


class SoundManager:
    """Manager for sound effects"""
    
    def __init__(self):
        self.audio_folder = get_resource_path("audio")
        self.sounds_enabled = True
        self.sound_effects = {}
        self.last_global_sound_time = 0
        self.min_sound_interval = 100  # Minimum interval between global sounds in milliseconds
        
    def set_enabled(self, enabled):
        """Enables or disables sounds"""
        self.sounds_enabled = enabled
    
    def play_sound(self, sound_file, is_global_action=False):
        """Plays sound file with optional global action rate limiting"""
        if not self.sounds_enabled:
            return
        
        # Rate limiting for global actions to prevent double sounds
        if is_global_action:
            current_time = QDateTime.currentMSecsSinceEpoch()
            time_since_last = current_time - self.last_global_sound_time
            
            if time_since_last < self.min_sound_interval:
                # Too soon after last global sound, skip this one
                return
            self.last_global_sound_time = current_time
        
        sound_path = os.path.join(self.audio_folder, sound_file)
        
        if os.path.exists(sound_path):
            try:
                # Use QSoundEffect for playback
                sound_effect = QSoundEffect()
                sound_effect.setSource(QUrl.fromLocalFile(os.path.abspath(sound_path)))
                sound_effect.setVolume(1.0)
                sound_effect.play()
                
                # Store reference so object isn't immediately deleted
                if sound_file not in self.sound_effects:
                    self.sound_effects[sound_file] = []
                self.sound_effects[sound_file].append(sound_effect)
                
                # Clean up old sound effects
                self.cleanup_old_effects()
                
            except Exception as e:
                print(f"Error playing sound {sound_file}: {e}")
        else:
            print(f"Audio file not found: {sound_path}")
    
    def cleanup_old_effects(self):
        """Cleans up old completed sound effects"""
        for sound_file in list(self.sound_effects.keys()):
            # Keep only the last 5 effects for each file
            if len(self.sound_effects[sound_file]) > 5:
                self.sound_effects[sound_file] = self.sound_effects[sound_file][-5:]
    
    def play_block_in(self, is_global_action=False):
        """Plays block IN traffic sound"""
        self.play_sound("Blocked_IN.wav", is_global_action)
    
    def play_block_out(self, is_global_action=False):
        """Plays block OUT traffic sound"""
        self.play_sound("Blocked_OUT.wav", is_global_action)
    
    def play_unblock_in(self, is_global_action=False):
        """Plays unblock IN traffic sound"""
        self.play_sound("Unblocked_IN.wav", is_global_action)
    
    def play_unblock_out(self, is_global_action=False):
        """Plays unblock OUT traffic sound"""
        self.play_sound("Unblocked_OUT.wav", is_global_action)
    
    def play_block_all(self, is_global_action=False):
        """Plays block ALL traffic sound"""
        self.play_sound("Blocked_ALL.wav", is_global_action)
    
    def play_unblock_all(self, is_global_action=False):
        """Plays unblock ALL traffic sound"""
        self.play_sound("Unblocked_ALL.wav", is_global_action)
    
    def create_dummy_sound_files(self):
        """Creates simple WAV files for testing if they don't exist"""
        import wave
        import struct
        
        sound_files = {
            "Blocked_IN.wav": 440,   # A4
            "Blocked_OUT.wav": 523,  # C5
            "Unblocked_IN.wav": 659, # E5
            "Unblocked_OUT.wav": 784, # G5
            "Blocked_ALL.wav": 880,  # A5
            "Unblocked_ALL.wav": 1047 # C6
        }
        
        for filename, frequency in sound_files.items():
            filepath = os.path.join(self.audio_folder, filename)
            if not os.path.exists(filepath):
                self.generate_sine_wave(filepath, frequency)
    
    def generate_sine_wave(self, filename, frequency=440, duration=0.5, volume=0.5):
        """Generates simple sine wave for testing"""
        try:
            sample_rate = 44100
            num_samples = int(sample_rate * duration)
            
            with wave.open(filename, 'w') as wav_file:
                # Set WAV file parameters
                wav_file.setnchannels(1)  # Mono
                wav_file.setsampwidth(2)  # 16-bit
                wav_file.setframerate(sample_rate)
                
                # Generate sine wave
                for i in range(num_samples):
                    # Sine wave
                    value = int(volume * 32767.0 * 
                              math.sin(2.0 * math.pi * frequency * i / sample_rate))
                    # Write as 16-bit integer
                    data = struct.pack('<h', value)
                    wav_file.writeframes(data)
        except Exception as e:
            print(f"Error creating file {filename}: {e}")


class BlockStatusManager:
    """Manager for handling block status persistence in INI file"""
    
    def __init__(self):
        self.ini_file = "block_status.ini"
        self.config = configparser.ConfigParser()
        self.block_status = {}
        self.load_status()
    
    def load_status(self):
        """Loads block status from INI file"""
        if os.path.exists(self.ini_file):
            try:
                self.config.read(self.ini_file, encoding='utf-8')
                
                # Load all IPs and their statuses from INI
                for section in self.config.sections():
                    if section.startswith('IP_'):
                        ip = section[3:]  # Remove 'IP_' prefix
                        in_blocked = self.config.getboolean(section, 'in_blocked', fallback=False)
                        out_blocked = self.config.getboolean(section, 'out_blocked', fallback=False)
                        self.block_status[ip] = {'in': in_blocked, 'out': out_blocked}
            except Exception as e:
                print(f"Error loading INI file: {e}")
                # Create new file if corrupted
                self.block_status = {}
                self.save_status()
        else:
            # Create new INI file
            self.save_status()
    
    def save_status(self):
        """Saves block status to INI file"""
        try:
            # Clear existing config
            self.config.clear()
            
            # Add settings section
            if not self.config.has_section('Settings'):
                self.config.add_section('Settings')
            
            # Add each IP with its status
            for ip, status in self.block_status.items():
                section_name = f'IP_{ip}'
                if not self.config.has_section(section_name):
                    self.config.add_section(section_name)
                self.config.set(section_name, 'in_blocked', str(status['in']).lower())
                self.config.set(section_name, 'out_blocked', str(status['out']).lower())
            
            # Write to file
            with open(self.ini_file, 'w', encoding='utf-8') as configfile:
                self.config.write(configfile)
        except Exception as e:
            print(f"Error saving INI file: {e}")
    
    def update_status(self, ip, status):
        """Updates status for specific IP"""
        self.block_status[ip] = status
        self.save_status()
    
    def remove_ip(self, ip):
        """Removes IP from INI file"""
        if ip in self.block_status:
            del self.block_status[ip]
            
            # Also remove from config
            section_name = f'IP_{ip}'
            if self.config.has_section(section_name):
                self.config.remove_section(section_name)
            
            self.save_status()
            return True
        return False
    
    def cleanup_orphaned_ips(self, current_ips):
        """Removes IPs that are in INI but not in current list"""
        ips_to_remove = []
        for ip in self.block_status.keys():
            if ip not in current_ips:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            self.remove_ip(ip)
        
        return ips_to_remove
    
    def get_status(self, ip):
        """Gets status for specific IP"""
        return self.block_status.get(ip, {'in': False, 'out': False})
    
    def get_all_blocked_ips(self):
        """Returns all IPs with any blocking"""
        blocked_ips = []
        for ip, status in self.block_status.items():
            if status['in'] or status['out']:
                blocked_ips.append(ip)
        return blocked_ips


class SettingsManager:
    """Manager for handling settings"""
    
    def __init__(self):
        self.config_file = "settings.ini"
        self.config = configparser.ConfigParser()
        self.load_settings()
    
    def load_settings(self):
        """Loads settings from file"""
        if os.path.exists(self.config_file):
            try:
                self.config.read(self.config_file, encoding='utf-8')
            except:
                # Create default settings if file is corrupted
                self.config['Settings'] = {
                    'sounds_enabled': 'true',
                    'global_block_enabled': 'true'
                }
                self.save_settings()
        else:
            # Create default settings
            self.config['Settings'] = {
                'sounds_enabled': 'true',
                'global_block_enabled': 'true'
            }
            self.save_settings()
    
    def save_settings(self):
        """Saves settings to file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as configfile:
                self.config.write(configfile)
        except Exception as e:
            print(f"Error saving settings: {e}")
    
    def get_sounds_enabled(self):
        """Returns sound status"""
        return self.config.getboolean('Settings', 'sounds_enabled', fallback=True)
    
    def set_sounds_enabled(self, enabled):
        """Sets sound status"""
        self.config.set('Settings', 'sounds_enabled', str(enabled).lower())
        self.save_settings()
    
    def get_global_block_enabled(self):
        """Returns global block checkbox status"""
        return self.config.getboolean('Settings', 'global_block_enabled', fallback=True)
    
    def set_global_block_enabled(self, enabled):
        """Sets global block checkbox status"""
        self.config.set('Settings', 'global_block_enabled', str(enabled).lower())
        self.save_settings()


class IPBlockerApp(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        self.firewall_manager = FirewallRuleManager()
        self.ip_manager = IPAddressManager()
        self.sound_manager = SoundManager()
        self.settings_manager = SettingsManager()
        self.block_status_manager = BlockStatusManager()
        self.hotkey_manager = HotkeyManager()
        
        self.current_selected_ip = None
        self.ip_block_status = {}  # Stores blocking status for each IP or range
        self.global_block_enabled = True  # Default enabled as requested
        
        # Set window icon using resource path
        self.set_window_icon(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "logo.ico"))
        
        self.init_ui()
        self.load_ip_addresses()
        self.sync_block_status_with_firewall()
        
        # Load settings
        sounds_enabled = self.settings_manager.get_sounds_enabled()
        self.global_block_enabled = self.settings_manager.get_global_block_enabled()
        self.sound_manager.set_enabled(sounds_enabled)
        self.sound_checkbox.setChecked(sounds_enabled)
        self.global_block_checkbox.setChecked(self.global_block_enabled)
        
        # Setup hotkeys
        self.setup_hotkeys()

    def set_window_icon(self, icon_path):
        """Set window icon from resource path"""
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
            self.setWindowIcon(icon)
        else:
            print(f"Icon not found at: {icon_path}")

    def init_ui(self):
        """Initializes user interface"""
        self.setWindowTitle('CheatersBlocker by Victorch4')
        self.setGeometry(100, 100, 950, 650)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        
        # Table for IP addresses and ranges
        main_layout.addWidget(QLabel('Loaded IP addresses and ranges:'))
        
        self.ip_table = QTableWidget()
        self.ip_table.setColumnCount(5)
        self.ip_table.setHorizontalHeaderLabels(['IP Address/Range', 'Type', 'Status', 'IN Traffic', 'OUT Traffic'])
        self.ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ip_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ip_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ip_table.itemSelectionChanged.connect(self.on_ip_selected)
        
        main_layout.addWidget(self.ip_table)
        
        # Control buttons frame
        control_frame = QGroupBox('Traffic Blocking Control')
        control_layout = QVBoxLayout()
        
        # Button for IN and OUT traffic with F1 label
        self.both_toggle = ToggleButton(
            'Unblock IN and OUT traffic (F1)',
            'Block IN and OUT traffic (F1)'
        )
        self.both_toggle.clicked.connect(lambda: self.handle_toggle('both'))
        
        # Button for IN traffic with F2 label
        self.in_toggle = ToggleButton(
            'Unblock IN traffic (F2)',
            'Block IN traffic (F2)'
        )
        self.in_toggle.clicked.connect(lambda: self.handle_toggle('in'))
        
        # Button for OUT traffic with F3 label
        self.out_toggle = ToggleButton(
            'Unblock OUT traffic (F3)',
            'Block OUT traffic (F3)'
        )
        self.out_toggle.clicked.connect(lambda: self.handle_toggle('out'))
        
        control_layout.addWidget(self.both_toggle)
        control_layout.addWidget(self.in_toggle)
        control_layout.addWidget(self.out_toggle)
        control_frame.setLayout(control_layout)
        
        main_layout.addWidget(control_frame)
        
        # Range info label
        self.range_info_label = QLabel('')
        self.range_info_label.setStyleSheet("color: #888888; font-style: italic;")
        self.range_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.range_info_label)
        
        # Settings frame
        settings_frame = QGroupBox('Settings')
        settings_layout = QHBoxLayout()
        
        # Checkbox for sounds
        self.sound_checkbox = QCheckBox('Enable sounds')
        self.sound_checkbox.setChecked(True)
        self.sound_checkbox.stateChanged.connect(self.on_sound_checkbox_changed)
        settings_layout.addWidget(self.sound_checkbox)
        
        # Checkbox for global block from pastebin - enabled by default as requested
        self.global_block_checkbox = QCheckBox('Enable blocking for ALL IPs/ranges from database')
        self.global_block_checkbox.setChecked(True)
        self.global_block_checkbox.stateChanged.connect(self.on_global_block_checkbox_changed)
        settings_layout.addWidget(self.global_block_checkbox)
        
        # Add stretch to align checkboxes
        settings_layout.addStretch()
        
        # Add "Our Discord" link
        self.discord_label = QLabel('Our Discord')
        self.discord_label.setStyleSheet("""
            QLabel {
                color: #7289DA;
                text-decoration: underline;
                font-weight: bold;
                padding: 2px;
            }
            QLabel:hover {
                color: #677BC4;
                background-color: rgba(114, 137, 218, 0.1);
                border-radius: 3px;
            }
        """)
        self.discord_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.discord_label.mousePressEvent = self.open_discord_link
        settings_layout.addWidget(self.discord_label)
        
        settings_frame.setLayout(settings_layout)
        
        main_layout.addWidget(settings_frame)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('Ready. Hotkeys: F1/F2/F3. Global block is ENABLED')
        
        # Update button states
        self.update_buttons_state()
    
    def open_discord_link(self, event):
        """Opens Discord link when clicked"""
        QDesktopServices.openUrl(QUrl("https://discord.gg/KuSjuvXCqM"))
    
    def setup_hotkeys(self):
        """Sets up hotkey handling"""
        # Connect signal from hotkey manager
        self.hotkey_manager.hotkey_signal.connect(self.handle_hotkey)
        
        # Start hotkey processing thread
        self.hotkey_manager.start()
    
    def handle_hotkey(self, key_id):
        """Hotkey handler"""
        # Update UI in main thread
        QMetaObject.invokeMethod(self, "_process_hotkey", 
                               Qt.ConnectionType.QueuedConnection,
                               Q_ARG(int, key_id))
    
    @pyqtSlot(int)
    def _process_hotkey(self, key_id):
        """Processes hotkey in main thread"""
        if not self.current_selected_ip:
            # Just show message in status bar
            self.status_bar.showMessage("Select an IP address or range in the table", 3000)
            return
        
        # Get current status
        current_status = self.ip_block_status.get(self.current_selected_ip, {'in': False, 'out': False})
        
        # Determine action based on key and current status
        if key_id == 1:  # F1 - IN and OUT
            # If both are blocked, unblock both. Otherwise, block both.
            if current_status['in'] and current_status['out']:
                self.perform_action('both', 'unblock')
            else:
                self.perform_action('both', 'block')
                
        elif key_id == 2:  # F2 - IN
            # Toggle IN state
            if current_status['in']:
                self.perform_action('in', 'unblock')
            else:
                self.perform_action('in', 'block')
                
        elif key_id == 3:  # F3 - OUT
            # Toggle OUT state
            if current_status['out']:
                self.perform_action('out', 'unblock')
            else:
                self.perform_action('out', 'block')
    
    def perform_action(self, direction, action):
        """Performs block or unblock action for IP or IP range"""
        # If global block is enabled, apply action to ALL loaded IPs
        if self.global_block_enabled:
            self.perform_global_action(direction, action)
            return
        
        # Original behavior - apply action only to selected IP
        ip_entry = self.current_selected_ip
        self.perform_single_action(ip_entry, direction, action)
    
    def perform_single_action(self, ip_entry, direction, action):
        """Performs action for a single IP entry"""
        is_range = self.ip_manager.is_range(ip_entry)
        
        try:
            if action == 'block':
                # Blocking
                self.firewall_manager.create_rule(ip_entry, direction)
                
                # Update local status
                if direction == 'both':
                    self.ip_block_status[ip_entry]['in'] = True
                    self.ip_block_status[ip_entry]['out'] = True
                elif direction == 'in':
                    self.ip_block_status[ip_entry]['in'] = True
                elif direction == 'out':
                    self.ip_block_status[ip_entry]['out'] = True
                
                # Update INI file
                self.block_status_manager.update_status(ip_entry, self.ip_block_status[ip_entry])
                
                direction_text = self._get_direction_text(direction)
                if is_range:
                    message = f'Blocked {direction_text} traffic for IP range: {ip_entry}'
                else:
                    message = f'Blocked {direction_text} traffic for {ip_entry}'
                self.status_bar.showMessage(message)
                
                # Play appropriate sound (not a global action)
                self.play_sound_for_action('block', direction, is_global_action=False)
                
            else:  # unblock
                # Unblocking
                self.firewall_manager.delete_rule(ip_entry, direction)
                
                # Update local status
                if direction == 'both':
                    self.ip_block_status[ip_entry]['in'] = False
                    self.ip_block_status[ip_entry]['out'] = False
                elif direction == 'in':
                    self.ip_block_status[ip_entry]['in'] = False
                elif direction == 'out':
                    self.ip_block_status[ip_entry]['out'] = False
                
                # Update INI file
                self.block_status_manager.update_status(ip_entry, self.ip_block_status[ip_entry])
                
                direction_text = self._get_direction_text(direction)
                if is_range:
                    message = f'Unblocked {direction_text} traffic for IP range: {ip_entry}'
                else:
                    message = f'Unblocked {direction_text} traffic for {ip_entry}'
                self.status_bar.showMessage(message)
                
                # Play appropriate sound (not a global action)
                self.play_sound_for_action('unblock', direction, is_global_action=False)
            
            # Update display in table
            self.update_table_status(ip_entry, self.ip_block_status[ip_entry])
            
            # Update button states based on new status
            self.update_button_states()
            
        except Exception as e:
            error_msg = f'Failed to change blocking state: {str(e)}'
            self.status_bar.showMessage(error_msg)
    
    def perform_global_action(self, direction, action):
        """Performs block or unblock action for ALL loaded IPs and ranges"""
        all_entries = self.ip_manager.get_ips()
        total_entries = len(all_entries)
        processed = 0
        errors = 0
        
        # Show processing message
        processing_msg = f"{'Blocking' if action == 'block' else 'Unblocking'} {direction} traffic for ALL {total_entries} IPs/ranges..."
        self.status_bar.showMessage(processing_msg)
        
        # Play sound ONCE for the entire global action
        self.play_sound_for_action(action, direction, is_global_action=True)
        
        # Process each entry WITHOUT playing individual sounds
        for ip_entry in all_entries:
            try:
                self.perform_single_action_silent(ip_entry, direction, action)
                processed += 1
                
            except Exception as e:
                errors += 1
                print(f"Error processing {ip_entry}: {e}")
        
        # Show completion message
        direction_text = self._get_direction_text(direction)
        action_text = 'blocked' if action == 'block' else 'unblocked'
        result_msg = f"Global action completed: {action_text} {direction_text} traffic for {processed}/{total_entries} entries"
        if errors > 0:
            result_msg += f" ({errors} errors)"
        self.status_bar.showMessage(result_msg)
    
    def perform_single_action_silent(self, ip_entry, direction, action):
        """Performs action for a single IP entry without playing sound"""
        try:
            if action == 'block':
                # Blocking
                self.firewall_manager.create_rule(ip_entry, direction)
                
                # Update local status
                if direction == 'both':
                    self.ip_block_status[ip_entry]['in'] = True
                    self.ip_block_status[ip_entry]['out'] = True
                elif direction == 'in':
                    self.ip_block_status[ip_entry]['in'] = True
                elif direction == 'out':
                    self.ip_block_status[ip_entry]['out'] = True
                
                # Update INI file
                self.block_status_manager.update_status(ip_entry, self.ip_block_status[ip_entry])
                
            else:  # unblock
                # Unblocking
                self.firewall_manager.delete_rule(ip_entry, direction)
                
                # Update local status
                if direction == 'both':
                    self.ip_block_status[ip_entry]['in'] = False
                    self.ip_block_status[ip_entry]['out'] = False
                elif direction == 'in':
                    self.ip_block_status[ip_entry]['in'] = False
                elif direction == 'out':
                    self.ip_block_status[ip_entry]['out'] = False
                
                # Update INI file
                self.block_status_manager.update_status(ip_entry, self.ip_block_status[ip_entry])
            
            # Update display in table
            self.update_table_status(ip_entry, self.ip_block_status[ip_entry])
            
        except Exception as e:
            raise e
    
    def sync_block_status_with_firewall(self):
        """Synchronizes firewall rules with INI file status on startup"""
        current_ips = self.ip_manager.get_ips()
        
        # Get IPs that are in INI but not in current list (orphaned)
        orphaned_ips = self.block_status_manager.cleanup_orphaned_ips(current_ips)
        
        # Remove firewall rules for orphaned IPs (asynchronously)
        if orphaned_ips:
            QTimer.singleShot(100, lambda: self._remove_orphaned_rules(orphaned_ips))
        
        # Apply blocking from INI file to current IPs
        for ip in current_ips:
            status = self.block_status_manager.get_status(ip)
            self.ip_block_status[ip] = status
            
            # Apply firewall rules based on status (asynchronously to avoid UI freeze)
            if status['in']:
                QTimer.singleShot(50, lambda ip=ip: self._apply_rule_async(ip, 'in'))
            
            if status['out']:
                QTimer.singleShot(75, lambda ip=ip: self._apply_rule_async(ip, 'out'))
            
            # Update table display
            self.update_table_status(ip, status)
    
    def _remove_orphaned_rules(self, orphaned_ips):
        """Asynchronously removes firewall rules for orphaned IPs"""
        for ip in orphaned_ips:
            status = self.block_status_manager.get_status(ip)
            if status['in']:
                try:
                    self.firewall_manager.delete_rule(ip, 'in')
                except:
                    pass
            if status['out']:
                try:
                    self.firewall_manager.delete_rule(ip, 'out')
                except:
                    pass
    
    def _apply_rule_async(self, ip, direction):
        """Asynchronously applies a firewall rule"""
        try:
            self.firewall_manager.create_rule(ip, direction)
        except:
            pass  # Rule might already exist
    
    def update_button_states(self):
        """Updates button states based on current IP or range status"""
        if self.current_selected_ip and self.current_selected_ip in self.ip_block_status:
            status = self.ip_block_status[self.current_selected_ip]
            
            # Update both toggle based on actual status
            self.both_toggle.set_state(status['in'] and status['out'])
            self.in_toggle.set_state(status['in'])
            self.out_toggle.set_state(status['out'])
    
    def load_ip_addresses(self):
        """Loads IP addresses and ranges from URL on startup"""
        self.status_bar.showMessage('Loading IP addresses and ranges...')
        
        url = "https://pastebin.com/raw/5M4Ciz6m"
        success, result = self.ip_manager.load_from_url(url)
        
        if success:
            all_entries = result
            self.ip_table.setRowCount(len(all_entries))
            
            for i, entry in enumerate(all_entries):
                # Get status from block status manager (loaded from INI)
                status = self.block_status_manager.get_status(entry)
                self.ip_block_status[entry] = status
                
                # Entry cell
                entry_item = QTableWidgetItem(entry)
                entry_item.setFlags(entry_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.ip_table.setItem(i, 0, entry_item)
                
                # Type cell (IP or Range)
                if self.ip_manager.is_range(entry):
                    type_item = QTableWidgetItem('Range')
                    type_item.setForeground(QBrush(QColor(255, 140, 0)))  # Orange for range
                else:
                    type_item = QTableWidgetItem('Single IP')
                    type_item.setForeground(QBrush(QColor(0, 128, 0)))  # Green for single IP
                type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.ip_table.setItem(i, 1, type_item)
                
                # Status cell (will be updated by update_table_status)
                status_item = QTableWidgetItem('Not blocked')
                status_item.setFlags(status_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.ip_table.setItem(i, 2, status_item)
                
                # IN/OUT status cells
                in_text = 'Blocked' if status['in'] else 'Unblocked'
                out_text = 'Blocked' if status['out'] else 'Unblocked'
                
                in_status = QTableWidgetItem(in_text)
                in_status.setFlags(in_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.ip_table.setItem(i, 3, in_status)
                
                out_status = QTableWidgetItem(out_text)
                out_status.setFlags(out_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.ip_table.setItem(i, 4, out_status)
                
                # Update overall status
                self.update_table_status(entry, status)
            
            self.status_bar.showMessage(f'Loaded {len(all_entries)} entries ({len(self.ip_manager.ip_addresses)} IPs, {len(self.ip_manager.ip_ranges)} ranges)')
            
            if self.ip_table.rowCount() > 0:
                self.ip_table.selectRow(0)
            
        else:
            error_msg = result
            QMessageBox.critical(self, 'Loading Error', 
                                f'Failed to load IP addresses and ranges:\n{error_msg}')
            self.status_bar.showMessage('Loading error')
    
    def update_table_status(self, entry, status):
        """Updates status in table for specific IP or range"""
        for row in range(self.ip_table.rowCount()):
            if self.ip_table.item(row, 0).text() == entry:
                # Update overall status
                if status['in'] or status['out']:
                    block_text = 'Partially blocked'
                    if status['in'] and status['out']:
                        block_text = 'Fully blocked'
                    self.ip_table.item(row, 2).setText(block_text)
                else:
                    self.ip_table.item(row, 2).setText('Not blocked')
                
                # Update IN/OUT statuses
                in_text = 'Blocked' if status['in'] else 'Unblocked'
                out_text = 'Blocked' if status['out'] else 'Unblocked'
                
                self.ip_table.item(row, 3).setText(in_text)
                self.ip_table.item(row, 4).setText(out_text)
                break
    
    def on_ip_selected(self):
        """Handler for IP address or range selection in table"""
        selected_items = self.ip_table.selectedItems()
        if selected_items:
            self.current_selected_ip = selected_items[0].text()
            
            # Show range info if it's a range
            if self.ip_manager.is_range(self.current_selected_ip):
                try:
                    start_ip, end_ip = self.current_selected_ip.split('-')
                    start = ipaddress.IPv4Address(start_ip.strip())
                    end = ipaddress.IPv4Address(end_ip.strip())
                    total_ips = int(end) - int(start) + 1
                    
                except:
                    pass
            else:
                pass
            
            # Update button states based on current entry status
            self.update_button_states()
            
            if self.ip_manager.is_range(self.current_selected_ip):
                self.status_bar.showMessage(f'Selected IP range: {self.current_selected_ip}')
            else:
                self.status_bar.showMessage(f'Selected IP: {self.current_selected_ip}')
        else:
            self.current_selected_ip = None
        
        self.update_buttons_state()
    
    def update_buttons_state(self):
        """Updates button states based on selection"""
        has_selection = self.current_selected_ip is not None
        
        self.both_toggle.setEnabled(has_selection)
        self.in_toggle.setEnabled(has_selection)
        self.out_toggle.setEnabled(has_selection)
    
    def handle_toggle(self, direction):
        """Handler for button toggles - based on actual state, not button state"""
        if not self.current_selected_ip:
            QMessageBox.warning(self, 'Warning', 'Select an IP address or range from the table')
            return
        
        entry = self.current_selected_ip
        current_status = self.ip_block_status.get(entry, {'in': False, 'out': False})
        
        # Determine action based on current status
        if direction == 'both':
            # If both are blocked, unblock both. Otherwise, block both.
            if current_status['in'] and current_status['out']:
                self.perform_action('both', 'unblock')
            else:
                self.perform_action('both', 'block')
        elif direction == 'in':
            # Toggle IN state
            if current_status['in']:
                self.perform_action('in', 'unblock')
            else:
                self.perform_action('in', 'block')
        elif direction == 'out':
            # Toggle OUT state
            if current_status['out']:
                self.perform_action('out', 'unblock')
            else:
                self.perform_action('out', 'block')
    
    def play_sound_for_action(self, action, direction, is_global_action=False):
        """Plays sound based on action and direction"""
        if action == 'block':
            if direction == 'in':
                self.sound_manager.play_block_in(is_global_action)
            elif direction == 'out':
                self.sound_manager.play_block_out(is_global_action)
            elif direction == 'both':
                self.sound_manager.play_block_all(is_global_action)
        elif action == 'unblock':
            if direction == 'in':
                self.sound_manager.play_unblock_in(is_global_action)
            elif direction == 'out':
                self.sound_manager.play_unblock_out(is_global_action)
            elif direction == 'both':
                self.sound_manager.play_unblock_all(is_global_action)
    
    def _get_direction_text(self, direction):
        """Returns text description of direction"""
        direction_map = {
            'both': 'IN and OUT',
            'in': 'IN',
            'out': 'OUT'
        }
        return direction_map.get(direction, direction)
    
    def on_sound_checkbox_changed(self, state):
        """Handler for sound checkbox change"""
        enabled = state == Qt.CheckState.Checked.value
        self.sound_manager.set_enabled(enabled)
        self.settings_manager.set_sounds_enabled(enabled)
        
        if enabled:
            self.status_bar.showMessage('Sounds enabled')
        else:
            self.status_bar.showMessage('Sounds disabled')
    
    def on_global_block_checkbox_changed(self, state):
        """Handler for global block checkbox change"""
        enabled = state == Qt.CheckState.Checked.value
        self.global_block_enabled = enabled
        self.settings_manager.set_global_block_enabled(enabled)
        
        if enabled:
            self.status_bar.showMessage('Global block is ENABLED. F1/F2/F3 will apply to ALL IPs/ranges.')
        else:
            self.status_bar.showMessage('Global block is DISABLED. F1/F2/F3 will apply only to selected IP/range.')
    
    def closeEvent(self, event):
        """Window close handler - fast exit without cleaning rules"""
        # Stop hotkey handler first (non-blocking)
        if self.hotkey_manager.isRunning():
            self.hotkey_manager.stop()
            # Don't wait for thread to finish - let it exit naturally
            self.hotkey_manager.quit()
        
        # Accept event immediately for fast exit
        event.accept()


def check_admin_privileges():
    """Check if program is running with administrator privileges"""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        return is_admin
    except:
        return False


def show_admin_required_dialog():
    """Show dialog when administrator privileges are required"""
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)
    
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Icon.Warning)
    msg_box.setWindowTitle("Administrator Privileges Required")
    msg_box.setText("This program requires administrator privileges to modify Windows Firewall rules.")
    msg_box.setInformativeText("Please run the program as administrator.")
    
    # Set window icon if possible
    try:
        icon_path = get_resource_path(os.path.join("data", "logo.ico"))
        if os.path.exists(icon_path):
            msg_box.setWindowIcon(QIcon(icon_path))
    except:
        pass
    
    # Single button - OK (default)
    msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
    msg_box.setDefaultButton(QMessageBox.StandardButton.Ok)
    
    # Connect the close event
    def on_close():
        sys.exit(1)
    
    # Connect button click
    msg_box.finished.connect(on_close)
    
    # Show the dialog
    msg_box.exec()
    
    # Exit program
    sys.exit(1)


def main():
    """Main application startup function"""
    # Check for administrator privileges BEFORE creating main app
    if not check_admin_privileges():
        show_admin_required_dialog()
        return
    
    app = QApplication(sys.argv)
    
    window = IPBlockerApp()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
