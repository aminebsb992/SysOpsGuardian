# SysOpsGuardian 🛡️
[[https://img.shields.io/badge/Language-Python%203.11-3776AB?logo=python&logoColor=white]](https://www.python.org/)


```text
  ███████╗██╗   ██╗███████╗ ██████╗ ██████╗ ███████╗
  ██╔════╝╚██╗ ██╔╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ███████╗ ╚████╔╝ ███████╗██║   ██║██████╔╝███████╗
  ╚════██║  ╚██╔╝  ╚════██║██║   ██║██╔═══╝ ╚════██║
  ███████║   ██║   ███████║╚██████╔╝██║     ███████║
  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝
   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝


​SysOpsGuardian is an autonomous system administrator and Site Reliability Engineering (SRE) suite in Python. Rather than generating surface-level alerts, it diagnoses root causes using statistical analysis and machine learning hazard models, then executes automated, reversible remediation workflows with rollback guarantees.
​🌟 Key Modules
​1. In-Depth Cloud Resource Monitoring & Root-Cause Remediation
​Progressive Heap Memory Leaks: Uses rolling linear regression (R^2 > 0.75) to differentiate memory leaks from traffic spikes. Automatically expands cgroup memory limits (+30%) and triggers a zero-downtime rolling restart (maxSurge=25%, maxUnavailable=0).
​Database Connection Pool Exhaustion: Terminates orphaned idle in transaction sessions older than 300s and resets client pool limits when connections reach 88% while DB CPU remains under 40%.
​Unrotated Log Ballooning: Compresses runaway debug logs in place, safely truncates active file descriptors without service restarts, and offloads archives to S3/GCS.
​Storage IOPS Burst Exhaustion: Automatically upgrades EBS storage from GP2 to GP3 (6,000 IOPS / 250 MB/s) online without unmounting.
​Orphan Cloud Asset Reclamation: Identifies and decommissions unattached EBS volumes, unassociated Elastic IPs, and idle development instances.
​2. Automated Deep Security Remediation for Fast-Changing Software
​Runtime Container Intrusion Quarantine: Detects unauthorized interactive shells (/bin/sh) with active outbound C2 sockets, applies kernel network namespace drop rules (iptables -I OUTPUT -j DROP), saves forensic dumps, and deploys clean signed images (cosign) with read-only root filesystems.
​Supply-Chain Dependency Auto-Patching: Identifies weaponized transitive CVEs, updates lockfiles (package-lock.json / requirements.txt) with secure patch versions, and triggers automated hot-patch builds.
​Dynamic Secret Rotation & IAM Pruning: Revokes leaked static credentials across cloud identity providers, mints short-lived dynamic credentials in HashiCorp Vault (1h TTL), and prunes wildcard IAM policies to strictly observed API operations.
​3. Predictive Hardware Failure Analysis & Proactive Mitigation
Autonomous system administrator and SRE suite in Python. Diagnoses root causes using statistical models and executes automated, reversible remediation workflows with rollback guarantees.


🌟 Key Modules
1. In-Depth Cloud Resource Monitoring & Remediation
Memory Leaks: Differentiates progressive leaks from traffic surges using linear regression. Expands cgroup limits and performs zero-downtime rolling restarts.
Database Pool Starvation: Detects and force-terminates idle-in-transaction connections older than 300s.
Log Ballooning: Compresses runaway debug logs in place and offloads archives to S3/GCS.
EBS IOPS Optimization: Online volume upgrade from GP2 to GP3 without unmounting.
2. Deep Security Remediation for Fast-Changing Software
Runtime Container Quarantine: Isolates compromised containers via network drop rules, dumps forensics, and spawns clean signed images (cosign).
Dependency CVE Patching: Pins vulnerable transitive packages in lockfiles and triggers hot-patch builds.
Secret Rotation & IAM Pruning: Revokes leaked keys, mints short-lived Vault tokens, and prunes wildcard IAM policies.
3. Predictive Hardware Failure Analysis
Weibull Wear-Out Modeling: Predicts NVMe drive failure, rebuilding mirrors to hot spares and filing automated vendor RMAs.
ECC Memory Surge Mitigation: Soft-offlines degrading physical memory rows (soft_offline_page) and live-migrates guest VMs.
Thermal Core Parking: Parks degraded CPU cores via sysfs and caps governor frequencies to prevent thermal shutdowns.


🚀 Quick Start
Installation
git clone https://github.com/aminebsb992/SysOpsGuardian.git

cd SysOpsGuardian

pip install -r requirements.txt
Usage
# 1. Run root-cause diagnostic scan

python3 sysops_guardian.py scan

# 2. Simulate remediation in Dry-Run mode

python3 sysops_guardian.py remediate --dry-run

# 3. Execute active remediation plans

python3 sysops_guardian.py remediate

# 4. Run full interactive demonstration

python3 sysops_guardian.py demo


📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
