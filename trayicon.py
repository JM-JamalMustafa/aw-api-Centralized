import socket
import logging
import os
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import Dict, Optional

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QMenu, QSystemTrayIcon, QWidget

logger = logging.getLogger(__name__)

def get_env() -> Dict[str, str]:
    """
    Necessary for xdg-open to work properly when PyInstaller overrides LD_LIBRARY_PATH
    """
    env = dict(os.environ)  # Make a copy of the environment
    lp_key = "LD_LIBRARY_PATH"  # For GNU/Linux and *BSD.
    lp_orig = env.get(lp_key + "_ORIG")
    if lp_orig is not None:
        env[lp_key] = lp_orig  # Restore the original, unmodified value
    else:
        env.pop(lp_key, None)  # Remove if LD_LIBRARY_PATH was not set
    return env

def open_url(url: str) -> None:
    """Open URL based on the operating system."""
    if sys.platform == "linux":
        env = get_env()
        subprocess.Popen(["xdg-open", url], env=env)
    else:
        webbrowser.open(url)

def open_webui(root_url: str) -> None:
    """Open the dashboard in the default web browser."""
    print(f"Opening dashboard: {root_url}/dashboard")
    open_url(root_url + "/dashboard")

def open_apibrowser(root_url: str) -> None:
    """Open the API browser."""
    print(f"Opening API browser: {root_url}")
    open_url(root_url)

def open_dir(d: str) -> None:
    """Open a directory on the system."""
    if sys.platform == "win32":
        os.startfile(d)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", d])
    else:
        env = get_env()
        subprocess.Popen(["xdg-open", d], env=env)

class TrayIcon(QSystemTrayIcon):
    def __init__(
        self,
        manager: Optional[object],  # Replace this with your actual manager class if available
        icon: QIcon,
        parent: Optional[QWidget] = None,
        testing: bool = False,
    ) -> None:
        super().__init__(icon, parent)
        self._parent = parent
        self.setToolTip("ActivityWatch" + (" (testing)" if testing else ""))
        self.manager = manager
        self.testing = testing
        
        # Dynamically get the correct URL (use the local IP or localhost)
        self.root_url = self._get_current_url()  # Fetches the current URL dynamically

        self.activated.connect(self.on_activated)
        self._build_rootmenu()

    def _get_current_url(self) -> str:
        """Fetch the current URL dynamically by checking the local network address."""
        # Get the local machine IP (works on local network or localhost)
        local_ip = self.get_local_ip()

        # Set URL to local IP (or localhost if IP is not found)
        if local_ip:
            root_url = f"http://{local_ip}:5000"
        else:
            root_url = "http://127.0.0.1:5000"  # Default to localhost if no network interface found
        return root_url

    def get_local_ip(self) -> Optional[str]:
        """Get the local IP address of the machine."""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip != "127.0.0.1":
                return local_ip
        except Exception as e:
            logger.error(f"Error getting local IP: {e}")
        return None  # Fallback to None if unable to fetch IP

    def on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Handle the double-click activation of the tray icon."""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            open_webui(self.root_url)

    def _build_rootmenu(self) -> None:
        """Build the root menu for the system tray icon."""
        menu = QMenu(self._parent)

        if self.testing:
            menu.addAction("Running in testing mode")  # Just informational
            menu.addSeparator()

        # Actions in Tray Menu
        menu.addAction("Open Dashboard", lambda: open_webui(self.root_url))
        menu.addAction("Open API Browser", lambda: open_apibrowser(self.root_url))
        menu.addSeparator()

        # Modules Menu (Customizable based on your manager)
        modulesMenu = menu.addMenu("Modules")
        self._build_modulemenu(modulesMenu)

        menu.addSeparator()

        # Exit application
        exitIcon = QIcon.fromTheme("icon", QIcon("static/icon.png"))
        menu.addAction(exitIcon, "Exit", lambda: QApplication.quit())

        self.setContextMenu(menu)

    def _build_modulemenu(self, modulesMenu: QMenu) -> None:
        """Define items for the modules submenu (placeholder items)."""
        modulesMenu.addAction("Module 1", lambda: print("Module 1 action"))
        modulesMenu.addAction("Module 2", lambda: print("Module 2 action"))

def start_tray_icon():
    """Function to initialize and start the tray icon application."""
    app = QApplication([])  # Initialize QApplication
    tray_icon = TrayIcon(manager=None, icon=QIcon("static/icon.png"), testing=False)
    tray_icon.show()
    app.exec()

if __name__ == "__main__":
    start_tray_icon()
