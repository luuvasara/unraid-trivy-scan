**Trivy Scan**

Scans the images of your Docker containers, and optionally the Unraid OS itself, for known vulnerabilities with a pinned Trivy release and shows one row per CVE, with the affected images, OS files and packages, filters for severity and fix status, a dashboard tile and an optional header tab. The OS's own packages (Slackware now, RPM on a Fedora base) are matched against NVD's CPE data with a pinned Grype release, since Trivy has no feed for either. You choose which databases are kept on disk. Settings, Trivy Scan.
