# macOS Vulnerability Research Training
##### by Csaba Fitzl and Gergely Kalman

### Overview

This 3-day training focuses on macOS Vulnerability Research (VR) for beginner
to intermediate students. While intermediate topics will be discussed, the
course focuses on bringing security researchers up to speed with macOS's
unique protections and vulnerabilities.

This training focuses mostly on logic vulnerabilities as these are
hard to systemically mitigate, unlike memory corruptions. With the
recent trend of Apple's move towards shipping increasingly robust user and
kernelspace memory-protection mitigations it is our belief that
logic vulnerabilities are the future of VR on macOS.

Check out the full CFP here: [full curriculum](curriculum.md)



### Upcoming dates and locations

Zer0Con (Seoul, Korea): 2026-03-30 - 2026-04-01 [https://x.com/POC_Crew/status/2010970146337353966](official announcement)

#### To get notified about future dates please submit [this google form](https://docs.google.com/forms/d/1-K3mwxa8DW7VzYWBW9gAr5bhgT6SXJLymDeC15uwF5s/edit).

### Course prerequisites

Students should have the following skills in order to successfully participate
in the class:

- User level familiarity with macOS
- Capable of performing basic administrative tasks on macOS (change settings)
- Familiarity with basic security concepts
- Basic scripting skills in bash and Python
- Basic understanding of the C programming language
- Very basic understanding of ARM64 assembly


### Required software/hardware

- Apple Silicon hardware, which:
- is capable of running the latest version of macOS (Tahoe)
- is capable of running at least 1 VM
- has enough disk space to store 2 VMs (~100GB)
- has the latest version of Xcode (26) installed
- you are the admin user of, and can install software or change settings if
  required

### Trainer BIOs

**Csaba** is a Principal macOS Security Researcher working at Kandji, focusing on
vulnerability research and EDR detection development. He currently has over 100
CVEs issued by Apple for vulnerabilities ranging from simple info leaks to full
macOS exploit chains bypassing all security controls. He frequently presents
his findings on conferences, like BlackHat, Objective By The Sea, POC, and many
others. Prior Kandji Csaba worked for OffSec developing the EXP-312 training
about macOS exploitation.

**Gergely** is a independent security researcher working mainly on the
Apple Security Bounty program, with a research focus on logic vulnerabilities.
He has presented his findings at OBTSv6, and blogs at https://gergelykalman.com
So far he has found multiple user to root LPEs, multiple TCC bypasses, an app
sandbox escape, along with other bugs. He enjoys trying to exploit the
unexploitable, as evidenced by multiple bugs of his that were hiding in plain
sight for years or in one case, for decades.
