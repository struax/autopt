import os
import subprocess

# Function to check if a command is available
def is_installed(command):
    result = subprocess.run(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

# Function to install packages using git
def install_from_git(repo_url, folder_name=None):
    folder_name = folder_name or repo_url.split('/')[-1]
    if not os.path.exists(folder_name):
        subprocess.run(['git', 'clone', repo_url])
        print(f"{folder_name} installed.")
    else:
        print(f"{folder_name} already cloned.")

# Function to install packages via apt or similar if available
def install_with_package_manager(package):
    try:
        subprocess.run(['sudo', 'apt-get', 'install', '-y', package])
        print(f"{package} installed.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing {package}: {e}")

# Tools to check and install
tools = {
    "POC Seeker": {
        "check": "poc-seeker",
        "install": lambda: install_from_git("https://github.com/0xyassine/poc-seeker.git")
    },
    "ProjectDiscovery tools": {
        "check": "nuclei",  # Example ProjectDiscovery tool
        "install": lambda: install_from_git("https://github.com/projectdiscovery/nuclei.git", "nuclei")
    },
    "FFUF": {
        "check": "ffuf",
        "install": lambda: install_from_git("https://github.com/ffuf/ffuf.git")
    },
    "Nuclei WordPress templates": {
        "check": "nuclei-wordfence-cve",
        "install": lambda: install_from_git("https://github.com/topscoder/nuclei-wordfence-cve.git")
    },
    "Nikto": {
        "check": "nikto",
        "install": lambda: install_from_git("https://github.com/sullo/nikto.git")
    },
    "WPScan": {
        "check": "wpscan",
        "install": lambda: install_from_git("https://github.com/wpscanteam/wpscan.git")
    },
    "OpenSSL": {
        "check": "openssl",
        "install": lambda: install_with_package_manager("openssl")
    },
    "Python": {
        "check": "python3",
        "install": lambda: install_with_package_manager("python3")
    }
}

# Check and install tools
for tool_name, tool_info in tools.items():
    if is_installed(tool_info['check']):
        print(f"{tool_name} is already installed.")
    else:
        print(f"{tool_name} is not installed. Installing...")
        tool_info['install']()

print("All checks complete.")
