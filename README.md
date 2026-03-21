# NetGuard Toolkit

NetGuard Toolkit is a PowerShell-based network monitoring and diagnostic tool designed to detect, log, and explain connectivity issues in real time.

It focuses on identifying whether problems originate from your local network or your internet service provider (ISP), while keeping logs for later analysis.

---

##  Features

* Automatic default gateway detection
* Local (gateway) and internet connectivity checks
* Session packet loss tracking
* Rolling (live) packet loss monitoring
* Latency (ping) monitoring
* Basic plain-English diagnostics
* Daily log file generation
* Traceroute snapshots during outages
* Hop-loss snapshot logging when internet drops
* High latency and packet loss event logging

---

##  What It Does

NetGuard Toolkit continuously monitors your connection and helps determine:

* If your **router/local network** is down
* If your **ISP is not responding**
* If your connection is experiencing **high latency or packet loss**
* When outages occur and how long they last

Instead of just showing raw data, it provides simple output to help explain what’s happening.

---

## Getting Started

1. Open PowerShell
2. Navigate to the project folder (Example: cd Desktop\NetGuard-Toolkit)
3. Run the script .\monitor.ps1 -- If you get a script execution error, run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

```

---

##  Logs

Logs are automatically generated and saved daily. All you need todo is create a file on your desktop named "NetworkMonitorLogs"

They include:

* Connection status changes
* Packet loss events
* High latency events
* Traceroute results during outages

---

##  Requirements

* Windows
* PowerShell 7+ (Older versions may break the script or behave differently. If you test it on an older version and it works, feel free to share your results!)

---

##  Roadmap (Planned Features)

* Alert notifications (e.g., Pushover)
* JSON-based logging
* Web-based dashboard
* Suspicious network activity detection
* System health monitoring (CPU/RAM)
* Configurable settings file

---

##  Author

DFAsniper
