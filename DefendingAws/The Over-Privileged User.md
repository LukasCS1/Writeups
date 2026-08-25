# Room Name
The Over-Privileged User

## Room Overview
A developer, named Carl, joined the team and needed access to AWS. An overzealous admin, with little time to spare, gave him full Administrator rights directly.
"We'll scope it later", said the admin as he rushed to the next task.

Weeks pass, and the developer still has unrestricted access to every service and resource. What can come later is a security breach.

In this room, you will take on the role of a security analyst who audits user permissions, identifies and remediates misconfigurations, and develops a secure IAM deployment strategy.

## Category
AWS IAM Misconfiguration


## Incident Summary
Code Spaces was a company that provided code hosting and project management services built on AWS. It provided subversion and git hosting for development teams.
On June 17, 2014, Code Spaces was hit by a Distributed Denial-of-Service (DDoS) attack. This was not unusual for an internet-facing service, but the DDoS was only the opening move.
While the company was focused on mitigating the traffic flood, the attacker had already gained access to the Code Spaces AWS management console, specifically, the EC2 control panel. The attacker left messages inside the console with a Hotmail address, demanding a ransom to stop the attack.
When Code Spaces staff realized someone was inside their AWS console, they changed the panel passwords. But the attacker had already created multiple backdoor IAM logins. As soon as the attacker saw recovery attempts, they escalated and began deleting everything.
Within 12 hours, Code Spaces' production environment, backups, machine configurations, and even off-site backups were partially or completely destroyed. The company issued a final notice to customers stating that they could no longer operate and that the company would permanently shut down.

## Core Failure
The attacker succeeded because the compromised identity had unrestricted administrative access to the entire AWS account. There were no guardrails, no permission boundaries, no explicit deny policies to prevent destructive actions, no MFA requirement for sensitive operations, and no monitoring or alerts for IAM changes.

## Identification Process 
How you identified the misconfiguration — commands run, what they revealed.


## Remediation
Steps taken to fix it — commands, policy changes, config adjustments.

## Secure Build
How to implement this correctly from scratch — the right way to do it.


## Tools & Environment
- AWS CLI
- AWS Console




## Key Takeaways
- What the misconfiguration enables for an attacker
- The correct principle/control that prevents it
- Any relevant AWS-specific tooling worth noting
