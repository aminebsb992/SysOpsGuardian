# SysOpsGuardian 🛡️

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
