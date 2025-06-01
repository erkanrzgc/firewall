# PyQt5-Based Simple Windows Firewall Application

This project provides a basic graphical firewall interface for Windows, built with Python and PyQt5. It uses the WinDivert (pydivert) library to capture network traffic, apply user-defined rules, protect against DDoS attacks, and block specified websites. Real-time captured packets are displayed in a table, and actions are logged to a file.

---

## Features

* **Real-Time Packet Capture:** Captures TCP/UDP packets using WinDivert (pydivert).
* **Protocol & Port-Based Blocking:** Filters packets based on user-added rules such as `tcp`, `udp`, or `:80`.
* **IP\:Port-Based Blocking:** Blocks traffic matching specific IP and port combinations (e.g., `192.168.1.1:80`).
* **DDoS Protection:** Detects excessive traffic from a single source within 1-second and 10-second windows and automatically blacklists offending IPs temporarily.
* **Website Blocking:** Resolves user-input domains (e.g., `www.example.com`) to IP addresses and blocks traffic to/from those IPs.
* **Whitelist:** Automatically allows `127.0.0.1` and `::1` (localhost addresses).
* **Real-Time GUI:**

  * Displays captured packets in a table (Source IP, Destination IP, Protocol).
  * Shows applied rules and log messages in a text area.
  * Lists blocked websites.
* **Dark Theme & Modern Styling:**

  * PyQt5 CSS for a dark background, highlighted buttons, and legible fonts.
  * Button hover/pressed effects, custom title colors, increased row height, etc.

---

## Requirements

* **Operating System:** Windows (WinDivert only works on Windows)
* **Python Version:** Python 3.7 or higher
* **Libraries:**

  * PyQt5
  * pydivert
  * locale (standard Python library)
  * socket (standard Python library)
  * collections (standard Python library)
  * logging (standard Python library)

> **Note:**
>
> * You must have WinDivert installed on your PC. Follow the installation instructions on the [WinDivert GitHub page](https://github.com/basil00/Divert).
> * Run the application as an administrator, or packet capturing will fail.

---

## Installation

1. **Create a Python Virtual Environment (Optional)**
   It is recommended to create and activate a virtual environment.

   ```bash
   python -m venv venv
   venv\Scripts\activate  
   ```

2. **Install Required Packages**
   Install PyQt5 and pydivert with the following command:

   ```bash
   pip install PyQt5 pydivert
   ```

   * PyQt5: For the graphical user interface (GUI)
   * pydivert: For capturing and sending packets via WinDivert

3. **Install WinDivert**

   * Download the latest WinDivert release (e.g., `WinDivert2.3.0_x64.zip`) from the [WinDivert Releases](https://github.com/basil00/Divert/releases) page.
   * Extract the ZIP file and copy `WinDivert.dll` to `C:\Windows\System32` (for 64-bit) or `C:\Windows\SysWOW64` (for 32-bit).

4. **Organize Project Files**
   Place all Python files (e.g., `firewall_gui.py`) in a single folder.
   Update the path to your icon file (`1.ico`) in the code under the `icon_path` variable or in the GUI initialization.

---

## Usage

1. **Run as Administrator**
   Open Command Prompt or PowerShell as an administrator to ensure WinDivert can capture packets.

2. **Start the Application**
   Navigate to the folder containing the Python file and run:

   ```bash
   python firewall_gui.py
   ```

   (Replace `firewall_gui.py` with your file name if different.)

3. **Main Interface Sections**

   * **Start Firewall / Stop Firewall:**

     * Click “Start Firewall” to begin capturing packets.
     * Click “Stop Firewall” to stop capturing.
   * **Rules Section:**

     * Enter a port number (e.g., `80`), a protocol (`tcp`/`udp`), or an IP\:Port combination (e.g., `192.168.1.100:443`) in the text box and click “Add Rule.”
     * The new rule appears in the list and is logged in the “Applied Rules” section.
     * To remove a rule, select it in the list and click “Delete Selected Rule.”
   * **Network Traffic Table:**

     * Displays captured packets in real-time with Source IP, Destination IP, and Protocol.
   * **Applied Rules Text Area:**

     * Logs every rule addition, rule deletion, blocking event, and DDoS detection message.
   * **Blocked Websites List:**

     * Enter a domain (e.g., `www.example.com`) in the text box and click “Add Website.”
     * The application resolves the domain to an IP, adds it to the blocklist, and displays it in the list.

4. **DDoS Protection & Blacklist Management**

   * If a single source IP sends more than 10,000 packets in 1 second or more than 50,000 packets in 10 seconds, the IP is automatically blacklisted.
   * Blacklisted IPs remain blocked for 60 seconds before being removed.
   * Blacklist additions and removals are logged in the “Applied Rules” section.

5. **Log File**

   * All significant events (packet seen, rule-based blocking, DDoS detection, blacklist removal, etc.) are appended to `firewall_logs.txt` in the project folder.
   * Open this file with a text editor to review the history of actions.

---

## Project Structure

```
/project_root
│
├── firewall_gui.py       # Main application code (PyQt5 GUI + Firewall logic)
├── firewall_logs.txt     # Log file generated during runtime
├── 1.ico                 # Icon file (update the path in the code)
└── README.md             # This document
```

* **firewall\_gui.py**

  * Contains the `Firewall` class (extends `QThread`):

    * `run()` method handles packet capturing, rule checks, DDoS detection, and blacklist management.
    * Includes helper methods like `resolve_url_to_ip()` and `get_protocol_name()`.
  * Contains the `FirewallGUI` class (extends `QMainWindow`):

    * Builds the GUI using PyQt5 widgets (buttons, list views, text areas, tables).
    * Manages user interactions (`add_rule`, `delete_rule`, `add_website`, `start_firewall`, `stop_firewall`).
  * The `if __name__ == "__main__"` block:

    * Sets up the application icon, global CSS, window size, and launches the event loop.

---

## Example Rules & Use Cases

1. **Block All TCP Traffic**

   * In the “Rules” text box, enter `tcp` and click “Add Rule.”
   * All TCP packets will be blocked.
   * The “Applied Rules” text area shows `Rule Added: tcp`.

2. **Block Traffic on Port 80**

   * Enter `:80` in the “Rules” text box and click “Add Rule.”
   * Blocks any packet with source or destination port 80.
   * Logs `Rule Added: :80`.

3. **IP\:Port Blocking**

   * Enter `192.168.1.50:443` as a rule.
   * Blocks packets to/from IP `192.168.1.50` on port `443`.

4. **Blocking a Website (Domain-Based)**

   * Type `www.facebook.com` in the “Blocked Websites” text box and click “Add Website.”
   * Resolves the domain’s IP and blocks all packets to/from that IP.
   * The blocked entry appears as `facebook.com (XXX.XXX.XXX.XXX)`.

5. **Simulating a DDoS Attack**

   * If an IP sends more than 10,000 packets in one second:

     * The application logs `DDoS detected! Blacklisting X.X.X.X (1s=...,10s=...)`.
     * The IP is added to the blacklist and blocked for 60 seconds.

---

## Customization Tips

* **Icon File**

  * Change the path of `icon_path` to your own `.ico` file:

  ```python
  icon_path = r"C:\Path\To\YourIcon.ico"
  ```
* **CSS Styling**

  * Adjust colors, fonts, padding, and other style attributes inside `app.setStyleSheet(""" ... """)` to match your preferences.
* **DDoS Thresholds**

  * Modify the values `10000` (1-second window) and `50000` (10-second window) inside the `run()` method to customize sensitivity.
* **Blacklist Duration**

  * Update the `timeout` parameter in `remove_from_blacklist(self, ip, timeout=60)` to change how long an IP remains blacklisted.
* **Whitelist & Blacklist Defaults**

  * Edit `self.whitelist` and `self.blacklist` lists in the `Firewall` class to add or remove initial entries.

---

## Important Notes

* **Administrator Privileges:**
  Run the application as an administrator, or WinDivert will not be able to capture packets.
* **WinDivert Version:**
  Ensure the WinDivert DLL version matches your Windows architecture (x86 vs x64).
* **DNS Resolution Timeout:**
  The code sets a 2-second timeout (`socket.setdefaulttimeout(2)`) for domain resolution. Increase this if your DNS server is slow.

---

## License

This project is open-source under the **MIT License**. Feel free to copy, distribute, and modify it. Include a `LICENSE` file with the full license text.

---

> For detailed information or to contribute, please open an issue or pull request on the GitHub repository. Happy coding!
