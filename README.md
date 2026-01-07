# feedwalla

Feedwalla transforms **[Firewalla](https://firewalla.com)** block events — specifically **Internet Scanner** detections — into a clean, Open Source Threat Intelligence (OSINT) feed. The feed is **released daily at 10:00 AM UTC** as a **GitHub Release**, sourced from the **[Firewalla MSP](https://firewalla.net)** subscription.

---

## ✨ What is Feedwalla?

Feedwalla is an open-source threat intelligence project that publishes **atomic indicators** observed by Firewalla networks. By focusing on **actual firewall blocks** triggered by **internet-wide scanning activity**, Feedwalla provides defenders with timely and practical indicators suitable for automated ingestion.

The goal is simple:

- Turn real firewall blocks into actionable OSINT  
- Keep indicators atomic and easy to consume  
- Release consistently, predictably, and transparently  

---

## 🔌 How to Use

### Manual Download

Download the latest feed directly from the **GitHub Releases** page.

### Automated Ingestion

Feedwalla is designed for easy integration with:

- Firewalls  
- SIEM platforms  
- SOAR pipelines  
- IDS / IPS systems  
- Custom scripts  

---

## 🎯 Intended Use Cases

- Enrich firewall blocklists  
- Correlate scanner activity across environments  
- Threat hunting  
- Detection engineering  
- Security research  

---

## ⚠️ Disclaimer

- Indicators are provided **as-is**  
- Inclusion does **not guarantee malicious intent**, only observed scanner behavior  
- Always validate indicators against your own environment and risk tolerance  
