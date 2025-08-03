
# Malware Evasion Techniques

This repo contains a set of evasion techniques used by malware devalopers to bypass static analysis, signature detection

>⚠**Disclaimer:**
This project is for **educational ** purposes only. The author does **not condone** or support any malicious or illegal use of the code. Use responsibly and ethically.

## Description

Evasion techniques are a core component of modern malware and red team tooling. This project demonstrates several methods to obscure and later recover critical data like MAC addresses and IP addresses. The goal is to showcase how such techniques work, so that defenders and researchers can better understand and detect them.

*The repo currently includes*:

- **MAC Address Obfuscation/Deobfuscation**
- **IPv4 Address Obfuscation/Deobfuscation**
- **IPv6 Address Obfuscation/Deobfuscation**

Each technique transforms the original data into a non-obvious format to hinder detection, and provides a corresponding function to reverse the obfuscation.

##  Features

- Lightweight and simple C implementations.
- Can be easily integrated into other malware or red team projects.
- Helps blue teams understand how evasion is done in the wild.

 
## Getting Started
1. Clone the repository:

```bash
    git clone https://github.com/Zanebilal/-PayloadObfuscationTechniques

```
2.open the desired obfuscation technique in microsoft vscode
3. build the file in the solution mode

4. Run the executable file


## 📝 **Note :**   
The techniques in this repository represent only a small subset of available obfuscation methods. There are many advanced techniques such as encryption-based obfuscation, polymorphic transformations, steganography, and runtime code generation. This repository focuses on foundational examples to aid understanding and analysis.
