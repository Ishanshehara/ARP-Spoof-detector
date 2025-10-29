Intrusion Detection System (IDS) — Project Description & Run Guide

Great — here’s a clear, practical description of your IDS and a step‑by‑step run guide so anyone (you, teammates, or a reviewer) can run, test, and understand the project.

Project Description

This Python-based Intrusion Detection System (IDS) monitors network traffic in real time and raises alerts for suspicious activity. It provides two interfaces:

Terminal version (ids_terminal.py) — lightweight, SSH‑friendly CLI with colored alerts, periodic statistics, and text file logging. Ideal for servers and headless environments.

GUI version (ids_gui.py) — dark-themed desktop dashboard (Tkinter) with start/stop controls, live stats, alerts panel, and SQLite persistence. Ideal for local monitoring and demos.

A separate attack_simulator.py safely generates test attacks on localhost (or a specified IP) so you can validate detection logic without harming real networks. The project includes documentation (README.md, QUICKSTART.md, EXAMPLES.md) and a PROJECT_SUMMARY.md.

Detection Capabilities

SYN flood detection (threshold-based)

Port scan detection (per-source port count within time window)

Malformed packet detection (XMAS, NULL, invalid TCP flags)

Suspicious IP blacklist detection

Multi-level alert severities (INFO / WARNING / CRITICAL)

Real-time alerts + persistent logging (file for terminal, SQLite for GUI)

Live packet statistics and periodic summaries

Thread-safe and memory-efficient design with auto-cleanup

Technical Notes

Uses scapy for packet capture/parsing

GUI built with tkinter and stores alerts in ids_alerts.db

Terminal logs to alerts.log

Configurable thresholds and time windows via constants at top of scripts

Includes safeguards for safe localhost testing (simulator)

Prerequisites

Before running, ensure the host has:

Python 3.7+

scapy installed:
pip3 install scapy

For GUI: Tkinter (system package; e.g., sudo apt-get install python3-tk on Debian/Ubuntu)

Optional tools for advanced tests: nmap, hping3, nc/netcat

You should run capture scripts with root privileges (packet capture requires elevated permissions).

File overview (quick)

ids_terminal.py — CLI IDS

ids_gui.py — Desktop IDS with SQLite

attack_simulator.py — Safe test traffic generator

alerts.log — Terminal log (created at runtime)

ids_alerts.db — SQLite DB (GUI mode)

README.md, QUICKSTART.md, EXAMPLES.md, PROJECT_SUMMARY.md — docs
