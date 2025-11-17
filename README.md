# 🕵️‍♂️ Syscall Spy – eBPF Process Execution Monitor

> A beginner-friendly eBPF tool that logs every program execution (`execve` syscall) in real time.  
> Submitted to **[eBPF Summit: Hackathon Edition 2025](https://devpost.com/hackathons/eBPF-Summit-Hackathon-Edition-2025)** – **Starter Track**.

![Demo](https://via.placeholder.com/600x300?text=Demo+Video+Link+Below)

## 🎯 What It Does

`Syscall Spy` uses **eBPF (extended Berkeley Packet Filter)** to safely hook into the Linux kernel and monitor every time a new program is launched via the `execve` system call. It logs:

- Process name (e.g., `ls`, `ping`, `curl`)
- Timestamp (down to nanosecond precision)

All of this happens **without modifying the kernel**, **without root-level modules**, and with **minimal performance overhead** — thanks to eBPF’s safety guarantees.

> 🔍 **Note**: Process names are truncated to 15 characters (kernel limit for the `comm` field). Full command-line arguments are not captured to keep the project beginner-focused and reliable.

## 💡 Why I Built This

As a first-time eBPF learner, I wanted to:
- Understand how eBPF programs interact with the kernel
- Build something functional that demonstrates real-world tracing
- Contribute to the eBPF ecosystem in a simple, educational way

This project helped me grasp core concepts like:
- eBPF hooks (kprobes/syscalls)
- Kernel-to-userspace data sharing (perf buffers)
- Safe kernel instrumentation

## 🛠️ How to Run

### Prerequisites
- **Linux** (kernel ≥ 4.18, Ubuntu/Debian recommended)
- **Python 3**
- **BCC (BPF Compiler Collection)**

### Install dependencies:
```bash
sudo apt update
sudo apt install bpfcc-tools python3-bpfcc
```

## Run the spy
```
git clone https://github.com/your-username/syscall-spy.git
cd syscall-spy
sudo ./spy.py
```
 # Trigger Events 
```
In another terminal, run any command: 
ls
ping -c 1 google.com
curl --version
```
#💡 Tip: Close background apps (like VS Code) before testing to avoid noise from helper processes. 

📂 Project Structure 

    spy.c – eBPF program (kernel space)
    spy.py – Python loader and event printer (user space)
     

🎥 Demo Video 

Watch the 3-minute demo  
🧠 What I Learned 

    eBPF programs run safely inside the kernel without risking crashes.
    Tools like BCC simplify eBPF development for beginners.
    Real-time system observability is powerful — and accessible!
     

📜 License 

MIT 
🙌 Acknowledgements 

    Built with BCC 
    Inspired by tutorials from eBPF.io  and Liz Rice 
    Thanks to the eBPF Slack community for being so welcoming to newcomers!
     
