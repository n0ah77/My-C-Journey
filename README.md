# My-C-Journey
Documenting my journey learning C
Whenever I want to learn something complex, I use the ChatGPT DeepSearch feature to create a science based roadmap based on 20+ sources.


# Roadmap: Mastering Windows Red Team Tool & Malware Development
### Overview and Learning Strategy
This roadmap guides a cybersecurity professional (OSCP-level, M.Sc. in Cybersecurity) to become proficient in Windows red teaming tool development using C. It is structured for ~2 hours of focused daily study, leveraging evidence-backed learning techniques and project-based tasks. Consistent daily practice leads to better long-term retention than sporadic intensive sessions​
ALGOCADEMY.COM
. Incorporate active recall (write code from memory, explain concepts aloud) and spaced repetition (review topics after increasing intervals) – these methods dramatically improve retention and skill mastery​
ALGOCADEMY.COM

ALGOCADEMY.COM
. Each phase below builds on the previous, covering C programming fundamentals, Windows internals, malware development, stealth/evasion tactics, and full red team operations. Hands-on projects are included in each phase because project-based learning significantly enhances problem-solving skills and real-world readiness​
FRONTIERSIN.ORG
. Prioritize the recommended high-quality resources and focus areas for maximum impact.

### Phase 1 (Weeks 1-4): C Programming Foundations
Goals: Gain fluency in C language fundamentals and low-level programming concepts necessary for malware development. Even as an experienced security researcher, developing custom tooling requires mastery of pointers, memory management, and system-level coding. C offers the low-level control and minimal runtime footprint ideal for stealthy malware.
Key Learning Topics:

C syntax and core concepts: data types, control structures, functions, pointers, and memory allocation (malloc/free).

Pointer arithmetic and memory management (crucial for buffer manipulation and shellcode handling).

Working with the Windows C toolchain: using MS Visual Studio or MinGW to compile C code for Windows, linking against Windows libraries.

Debugging and safe coding practices: understanding stack vs. heap, avoiding common bugs (buffer overflows, off-by-one errors).

### Study & Practice Approach:

Dedicate ~2 hours daily to writing C code. Maintain consistency – the brain consolidates skills better with daily practice than with sporadic cramming​
ALGOCADEMY.COM
. If needed, split into Pomodoro cycles (e.g. 4×25 minutes) to stay focused.

Apply active recall: after learning a concept (e.g. pointers), close the book and implement a small example from scratch. Research shows retrieval practice yields significantly better long-term performance than passive review​
ALGOCADEMY.COM
.

Break problems into small chunks and gradually increase difficulty. This deliberate practice ensures you’re always pushing slightly beyond your comfort zone, which accelerates skill acquisition.

Use version control (Git) to track your code progress. Regularly revisit and refactor earlier code – this reinforces learning and highlights improvement areas.

## Hands-On Projects (Phase 1): (Aim for simple tools that solidify C basics)

FizzBuzz and Beyond: Write the classic FizzBuzz, then extend it (e.g. print prime numbers) to practice loops and conditionals.

Text File Parser: Write a C program to read a text file, count word frequencies, and output results. This exercises file I/O and dynamic memory (for storing counts).

Simple Calculator: Build a command-line calculator that parses basic arithmetic expressions. Reinforces string processing and use of pointers.

Memory Practice: Implement your own versions of strcpy, memcpy, etc. to understand buffer handling. (Deliberately practice careful pointer arithmetic and test for edge cases.)

Data Structures: Implement a simple linked list or binary tree in C. This will deepen your pointer mastery and memory allocation skills.

### Recommended Resources:

Books/Courses: The C Programming Language by Kernighan & Ritchie – a classic for C fundamentals. Follow its exercises to build a strong base. Consider Project Euler or Exercism.io C track for additional coding challenges.

Interactive Tutorials: “Security-Oriented C Tutorial” on NullByte (WonderHowTo) – introduces C with a security mindset. Also try free courses on Codecademy or freeCodeCamp for C basics (to brush up quickly).

Scientific Learning References: Review AlgoCademy’s Science of Learning blog for coding-specific study tips (active recall, spaced repetition)​
ALGOCADEMY.COM
​
ALGOCADEMY.COM
. Use a spaced repetition app (e.g. Anki flashcards) to memorize C syntax and pointers quirks – evidence shows spaced reviews yield superior retention over cramming​
ALGOCADEMY.COM
.

Community & Support: Engage with the C programming community (Stack Overflow, r/C_Programming on Reddit) when stuck. Explaining your code issues to others is a form of the Feynman technique that will improve your understanding.

## Phase 2 (Weeks 5-8): Windows Internals & Win32 API Basics
Goals: Build a deep understanding of Windows operating system internals and learn to interact with Windows APIs using C. This foundation is crucial – as one malware development guide notes, understanding the inner workings of Windows is crucial for security professionals​
SYSTEMWEAKNESS.COM
. You will learn how Windows processes, memory, and security mechanisms work, and how to leverage them for tool development. Mastering the Win32 API allows you to perform native actions (process creation, memory allocation, file/registry operations) that stealthy tools require. Modern adversaries favor custom tools using Windows APIs to avoid the easily-detected “noise” of public hacking tools​
INT0X33.MEDIUM.COM
. Key Learning Topics:

Windows Architecture & Components: Learn the structure of Windows (user mode vs. kernel mode, subsystems, HAL). Understand that normal programs run in user mode and must request kernel services via system calls​
MEDIUM.COM
. Know how the Win32 API acts as a bridge to the Native API (ntdll.dll) and then to the kernel​
MEDIUM.COM
.

Processes, Threads, and Memory: Study how Windows creates processes (PE program loading, CreateProcess internals) and manages threads. Key concepts: virtual memory layout, stacks/heaps, handles, and memory allocation functions (VirtualAlloc, VirtualProtect, etc.). Understand the Portable Executable (PE) file structure basics (headers, sections) – this will be vital when you start injecting code or hiding payloads in binaries.

Windows Security Model: Learn about user privileges, access tokens, and integrity levels. For example, how an access token with SeDebugPrivilege lets you read/write other process memory (critical for tools like credential dumpers)​
INT0X33.MEDIUM.COM
. Study how UAC and user groups affect what your code can do.

Win32 API Fundamentals: Practice using common Win32 functions in C. Important APIs: process management (CreateProcess, OpenProcess, TerminateProcess), memory management (VirtualAllocEx, WriteProcessMemory), libraries (LoadLibrary, GetProcAddress), file and registry functions (CreateFile, RegOpenKeyEx, etc.), and networking (Winsock socket, connect for later use in payloads). Also get comfortable with Windows data types (DWORD, HANDLE, LPSTR, etc.) and structures (STARTUPINFO, PROCESS_INFORMATION).

Tooling & Environment: Set up a Windows development VM (if not already) with Visual Studio or Mingw-w64 + VSCode. Learn to compile and run C programs on Windows, and use the Visual Studio Debugger or Windbg to step through simple programs (this helps you understand Windows API behaviors and error handling via GetLastError).

### Hands-On Projects (Phase 2): (Build simple enumeration and admin tools to apply Windows API knowledge)

Process Enumerator: Using C and the Win32 API, list all running processes with their PID, name, and perhaps parent process. Use APIs like CreateToolhelp32Snapshot and Process32First/Next or the newer EnumProcesses from PSAPI. This project teaches handle usage and reading another process’s info.

Privilege Checker: Write a tool to check the current process token for specific privileges (like SeDebugPrivilege). Use OpenProcessToken, GetTokenInformation, etc. This will familiarize you with Windows security APIs and structures (TOKEN_PRIVILEGES).

System Info Utility: Implement a “mini sysinfo” that prints OS version, username, hostname, and other environment details. Use APIs such as GetVersionEx, GetComputerName, GetUserName, and query environment variables. Extend it to enumerate running services (using EnumServicesStatusEx) and scheduled tasks (via COM or reading the Task Scheduler API) to practice interacting with various subsystems.

Basic Keylogger (optional): For a more advanced challenge, try writing a simple keylogger using SetWindowsHookEx with a WH_KEYBOARD_LL hook. This introduces Windows event-driven programming and the concept of DLL injection (as the hook procedure might reside in a DLL). Be cautious and do this in a lab environment only.

Memory Operations Demo: Allocate a chunk of memory with VirtualAlloc, write some data, change protections with VirtualProtect, and free it. Print addresses to understand memory layout. This low-level exercise will be useful when dealing with shellcode in Phase 3.

### Recommended Resources:

Books: Windows Internals, 7th Ed. by Mark Russinovich – an authoritative (if dense) reference to understand processes, threads, memory management, and security in Windows. Focus on chapters about process architecture, memory, and security for this phase. Windows System Programming, 4th Ed. by Johnson M. Hart – a more hands-on guide for using Win32 APIs in C/C++​
SECURITY.STACKEXCHANGE.COM
(covering files, registry, pipes, etc.) which aligns well with tool development.

Online Documentation: Microsoft’s official docs on Win32 API (the Learn Microsoft site) – e.g. read the “Getting Started with Win32” guides​
NULL-BYTE.WONDERHOWTO.COM
and API reference pages for each function you use. The documentation often has examples in C.

Blogs & Tutorials: Atumcell’s Windows API for Pentesting series – highlights how Windows API calls (with proper privileges) allow tasks like reading other processes’ memory, killing AV processes, etc.​
INT0X33.MEDIUM.COM
. This reinforces why custom tools using these APIs can mimic advanced adversary capabilities​
INT0X33.MEDIUM.COM
. Also explore ired.team’s Enumeration and Discovery notes, which show how to enumerate users, services, and tasks without using built-in commands (to stay covert)​
IRED.TEAM
– you can try implementing similar API-based enumeration in your projects.

Hands-On Labs: Consider the free Driver Explorer or WinObj tools from Sysinternals to visually explore processes, handles, etc. (Optional: try writing a simple clone of a tiny portion of their functionality, e.g. enumerating open windows or loaded drivers, if curious).

Community: Join Windows API programming discussions on forums. The subreddit r/WindowsProg or communities on Stack Exchange (e.g. StackOverflow’s WinAPI questions) can be invaluable when you encounter quirky Windows API behavior. Seeing common issues others face (and solutions) will accelerate your learning.

## Phase 3 (Weeks 9-12): Malware Development & Payload Engineering
Goals: Apply your C and Windows API skills to develop actual payloads and malicious tools. In this phase, you’ll learn to craft payloads (shellcode, backdoors) and execute them covertly. Key topics include the Portable Executable format, shellcode injection techniques, and basic evasion like encoding payloads. By the end of this phase, you should be able to create a simple Windows trojan/dropper that can deliver a payload (e.g. reverse shell or Meterpreter) into memory. According to a popular red team malware course, the essentials of malware dev include building droppers, injecting shellcode into remote processes, backdooring executables, and bypassing Defender AV​
SOLOMONSKLASH.IO
. We will focus on those fundamentals here.
Key Learning Topics:

Portable Executable (PE) File Basics: Understand the structure of a PE file (headers, sections like .text, .rdata, .data). Learn how malware often hides data in non-standard sections or the resource section of the PE​
GITHUB.COM
. Basic knowledge of PE helps in modifying or creating executables that blend in (and in Phase 4, to avoid static signatures).

Shellcode and Execution Methods: Learn what shellcode is (typically machine code for payloads such as reverse shells). Practice generating shellcode (e.g., use msfvenom to get a simple calc.exe shellcode or a Meterpreter stage). Study common shellcode injection techniques:

CreateRemoteThread Injection: Allocate memory in a target process (VirtualAllocEx), write shellcode (WriteProcessMemory), then create a remote thread (CreateRemoteThread) to execute it. This is a fundamental code injection method to run code in another process.

Process Hollowing: Create a process in suspended state (e.g. CreateProcess with CREATE_SUSPENDED flag), replace its memory (WriteProcessMemory) with malicious code, then resume it. This hides your payload in the context of a legitimate process.

Reflective DLL Injection: Concept of loading a DLL from memory rather than disk. (You might not implement fully yet, but understand that malware can carry a DLL in its binary and map it into memory to execute). Each technique has many resources and examples online – focus first on the CreateRemoteThread approach as it’s straightforward and foundational.

Covert Networking: Develop a simple reverse shell and/or C2 beacon. This involves using Windows sockets (Winsock2). Understand how to create a socket, connect to a server, and redirect input/output. Also get familiar with basic network evasion (e.g., using common ports like 443, or using HTTP to blend in). For now, implement a plain reverse TCP shell as a learning project.

Simple Persistance & Automation: Learn ways malware persists or triggers execution. E.g., adding a Run key in the Registry for your malware, or creating a scheduled task or service. Use C code to modify registry (RegCreateKey) or use CreateService Windows API to install a dummy service – this gives insight into how malware survives reboots.

Basic Obfuscation: Start practicing simple evasion for your payloads: XOR or AES-encrypt your shellcode in the source, and decrypt at runtime before execution. Understand that hardcoded strings or byte patterns can get flagged by AV; we mitigate this by encoding them. For instance, storing shellcode encrypted and decrypting in memory is a common tactic​
GITHUB.COM
. Also learn how to resolve API functions dynamically at runtime (using GetProcAddress on needed functions) instead of statically linking – this will make your binaries less suspicious to scanners.

Hands-On Projects (Phase 3): (Build and combine offensive capabilities in code)

Reverse Shell in C: Write a console program that connects back to a TCP listener on your attack machine and provides a simple shell (executes commands received). Use WSAStartup, socket, connect and then redirect stdin/stdout via CreateProcess (to spawn cmd.exe). This project solidifies networking and process creation in C. Test it on a lab Windows machine with a Netcat listener.

Shellcode Injector: Develop a tool that injects shellcode into another process. For example, have it take a process ID and a blob of shellcode, then perform: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread. Test by injecting a benign payload (like a MessageBox shellcode or launching calc.exe shellcode) into a notepad process. Ensure you handle 32-bit vs 64-bit differences if needed (on 64-bit Windows, a 32-bit process cannot inject into a 64-bit process easily).

Custom Dropper: Combine the above techniques to create a dropper executable. For instance, embed an encrypted shellcode payload in the binary (possibly in the resource section). When run, the dropper decrypts the payload and injects it into a target process (e.g., explorer.exe). Use function pointer obfuscation for API calls (as seen in Sektor7’s example, calling functions via pointers to avoid direct strings​
GITHUB.COM
). The dropper could deliver a Meterpreter shellcode or your reverse shell. Aim to have it run without writing the payload to disk (load from memory), which is a hallmark of modern malware.

Backdoor an Application: Take a small, harmless EXE (open-source or something like Putty) and practice adding a malicious code snippet to it. For example, modify its source (if available) or use a tool like a PE editor to insert a new section containing code that runs on startup (this could be just a PoC like writing a file or popping calc). This teaches how malware can trojanize legitimate software​
SOLOMONSKLASH.IO
. (Do this only in a lab setting.)

Unit-test Your Techniques: For each project, verify it works in various scenarios. For instance, test your injector on processes run as admin vs normal user, on 32-bit vs 64-bit processes, etc. These experiments deepen your understanding of Windows internals (like WOW64 differences, required privileges for certain API calls, etc.).

Recommended Resources:

Courses: RED TEAM Operator: Malware Development Essentials by Sektor7 – a highly practical course that covers developing a custom Windows dropper and injection techniques​
SOLOMONSKLASH.IO
​
SOLOMONSKLASH.IO
. If accessible, this course can accelerate your learning (it includes code samples for encryption, function hashing, PE manipulation, etc.).

Books: Practical Malware Development doesn’t have a well-known single textbook equivalent to PMA (Practical Malware Analysis) for coding, but consider Windows Malware Analysis by Uzair and Nakib (covers malware techniques on Windows, bridging analysis and development), or The Shellcoder’s Handbook (older, but chapters on Windows shellcode and injection are useful). The classic Hacking: The Art of Exploitation (2nd Ed) by Jon Erickson can reinforce low-level coding and injecting code (albeit on Linux) – it’s great for understanding how exploits and shellcode work at the C/assembly level.

Blogs/Write-ups: Explore freely available blog series on malware dev. For instance, 0xPat’s “Malware Development” blog posts and Smukx’s Malware Development Essentials (on System Weakness) share notes on Windows internals and maldev topics​
SYSTEMWEAKNESS.COM
. Also, the GitHub project maldev-essentials-assignment​
GITHUB.COM
contains an example dropper from the Sektor7 course, demonstrating encrypted payload and API obfuscation – reviewing such code (alongside your own attempts) can be instructive.

GitHub Repos: Study open-source or leaked red team tools for reference (read-only!). For example, check out the code for Metasploit’s Meterpreter payload (Windows portion written in C) or Cobalt Strike Beacon (older leaked source or community re-implementations). These show how professional implants manage communication, injection, and evasion. A simpler codebase is DanderSpritz’s Windows binaries (from the Shadow Brokers leak) which can give insight into real APT tooling.

Windows API Reference: Keep MSDN close at hand. When implementing injections or network code, read the official docs for each API to understand parameters and gotchas (e.g., CreateRemoteThread documentation notes about privileges needed, etc.). This will save you time debugging.

Community & Debugging: If you hit roadblocks (e.g., your injected code crashes the target process), leverage the community: forums, or even Twitter (#maldev hashtag). Debug systematically – use a debugger to attach to the target process and see what happens after injection. Learning to debug shellcode with WinDbg or x64dbg is a valuable skill in itself at this stage.

Phase 4 (Weeks 13-16): Advanced Stealth and Evasion Tactics
Goals: Elevate your custom tooling by integrating stealth techniques to evade Anti-Virus (AV), Endpoint Detection & Response (EDR) systems, and other defenses. Modern endpoint security is highly sophisticated, using behavioral analysis, heuristics, and memory scanning. As a red team tool developer, you must learn to bypass these defenses through obfuscation, abusing trusted processes, and misusing OS mechanisms. In this phase, focus on defense evasion tactics: making your code hard to detect both at rest and during execution. This includes evading static signature detection (via encoding/obfuscation and polymorphism) and bypassing runtime monitoring (via API unhooking, direct syscalls, disabling or avoiding sensors like AMSI and ETW). These skills map to MITRE ATT&CK’s Defense Evasion techniques and are critical for stealthy operations.
Key Learning Topics:

AV Signature Evasion: Understand how AV engines scan files for known byte signatures or heuristics. Practice refactoring your binaries to avoid static indicators:

Implement string obfuscation (e.g., encrypting or XORing any suspicious strings like "cmd.exe" or known bad API names, and decrypt at runtime only when needed).

Use polymorphism: automate simple changes in your code or compile process (inlining functions, reordering instructions) so each build hashes differently, preventing easy signature hits.

Utilize packers or crypters: experiment with tools like UPX (on a benign test binary) to see how packing works. Later, consider writing a simple packer stub that decrypts your payload at runtime. (Be mindful: packing can itself trigger alerts, so custom packers are better.)

Bypassing AMSI (Anti-Malware Scan Interface): AMSI is the Windows interface that scans scripts and memory for malware patterns (especially for PowerShell, VBA, etc.). Even C/C++ malware must sometimes disable AMSI if it plans to invoke PowerShell or run scripts. Learn the known AMSI bypass techniques:

Memory patching: e.g., patch the AmsiScanBuffer function in memory to always return a “clean” result. Daniel Duggan’s AMSI bypass accomplishes this by patching the function bytes to force a clean return code​
PENTESTLABORATORIES.COM
. You can replicate this by locating amsi.dll in your process and overwriting the first bytes of AmsiScanBuffer with a mov eax, 0x80070057; ret (for x64) which sets result to S_OK (no malware)​
PENTESTLABORATORIES.COM
.

COM abuse or reflection: Some bypasses use COM objects or .NET interop to disable AMSI by setting internal flags (e.g., the famous amsiInitFailed flag in AMSI’s .NET object). Understand the concept even if you implement the direct patch method in C/C++ for practice.

EDR Hook Evasion: EDR products often hook common API functions (by modifying the in-memory code of DLLs like kernel32.dll or ntdll.dll) to monitor malicious calls. Learn to identify and bypass these hooks:

API Unhooking: One approach is to manually reload a fresh copy of the hooked DLL (e.g., ntdll.dll) from disk and overwrite the in-memory one, thereby removing any hooks. This can be done by manually mapping the file or using Windows APIs to load it as data. There are open-source examples of this (e.g., Outflank’s ThreadStackSpoof or ired.team’s notes)​
IRED.TEAM
.

Direct System Calls: Instead of calling the high-level Win32 API (which EDR might hook), call the syscall inlined in ntdll.dll directly by using the syscall instruction. Tools like SysWhispers2 can generate wrapper functions that execute syscalls for selected APIs, bypassing user-mode hooks​
IRED.TEAM
. Practice integrating a syscall for one function (e.g., NtWriteVirtualMemory instead of WriteProcessMemory) in your injector and observe if it gets caught or not.

Function Stubbing: Similarly, you can copy just the unhooked bytes of a function from disk and call that stub. Learn how to detect hooks by checking the prologue bytes of functions in memory versus what’s expected (this is an advanced but insightful exercise, see ired.team’s Detecting Hooked Syscalls note​
IRED.TEAM
).

Process Injection & Masquerading Tricks: Refine your injection techniques to be more stealthy:

Process Masquerading: Spawn your malware process but make it look like a legitimate one (e.g., via CreateProcess with the Suspended flag and then spoofing the command line or parent process ID). For instance, Parent PID Spoofing is used to confuse lineage detection (tools exist to create processes with a chosen PPID)​
IRED.TEAM
. Research how to use documented or undocumented APIs to achieve this (there are code samples on GitHub).

Module Stomping / DLL Hollowing: Load a legitimate DLL in your process, then overwrite its sections with your payload (so in memory it looks like a known DLL module, but it’s running your code)​
IRED.TEAM
. This is complex but good to be aware of as an evasion: the concept is you’re hiding in a trusted DLL’s memory space.

Thread Context Tricks: Explore QueueUserAPC or NtQueueApcThread for injection that happens asynchronously in thread context (this can sometimes slip past certain API monitors). Also consider less common injection like SetThreadContext (used in process hollowing).

Living-off-the-Land Binaries (LOLBins): Study how to use built-in Windows tools for malicious ends (e.g., rundll32.exe to execute your DLL, msbuild.exe to run inline C#). While this is more operational tradecraft than coding, integrating LOLBins usage into your tool (or as a fallback) can increase stealth. For example, your implant could drop a payload to an Alternate Data Stream and use regsvr32 to execute it – all of which could be orchestrated via system calls in C. Knowing these techniques will inform how you design your tools (perhaps you’ll write less code if an OS feature can do it for you).

Anti-Analysis and Sensors: Learn how malware detects and disables analysis tools:

Sandbox Evasion: Check for virtualization or sandbox artifacts (registry keys, process names like vmtoolsd.exe for VMWare, low memory or single CPU environments) and have your code sleep or exit to frustrate automated sandboxes.

Event Tracing for Windows (ETW) Evasion: EDRs use ETW for telemetry. Advanced malware can disable ETW by patching EtwEventWrite in ntdll. Understand this as a parallel to AMSI patching. You might attempt a similar patch to turn off security event reporting.

Kernel vs User: Recognize that some EDR capabilities live in kernel (e.g., driver-based detection). Bypassing those might be out of scope (requires kernel exploits or signing; covered in advanced training), but be aware of the boundary. If you reach an EDR that you cannot bypass in userland, note it and move on – the focus here is on user-mode evasion.

Hands-On Projects (Phase 4): (Upgrade your Phase 3 tools with stealth features and test them against defenses)

Secure Loader with AMSI Bypass: Take your Phase 3 dropper or reverse shell and integrate an AMSI bypass. For example, if your tool executes PowerShell commands (maybe to perform some task), implement the memory patch to AMSI before launching PowerShell. Even if not, practice writing a function that locates amsi.dll in memory and patches AmsiScanBuffer as described in research​
PENTESTLABORATORIES.COM
. Verify that before patching, loading a known malicious script triggers Defender, and after patching, it runs. (Use a test VM with Windows Defender on.)

Unhooking Demo: Write a small utility that checks ntdll.dll in memory for hooks and restores it. One approach: use LoadLibrary("ntdll.dll") to get a fresh copy in a new memory region, then copy the text section over the existing ntdll in process memory. This is easier in C++ (due to accessing binary data), but can be done in C as well. Test by running this after an EDR or AV is installed, and see if it breaks any hooks (some EDRs might crash or lose visibility – do this in a controlled lab). This will teach you a lot about how hooking works.

Direct Syscalls in Injector: Modify your shellcode injection tool to use direct NT system calls for critical functions. For instance, replace CreateRemoteThread with NtCreateThreadEx syscall (using a library like SysWhispers to get the function). Test if the new variant is detected by antivirus less often. You can use open-source tools like ScareCrow or Donut to generate shellcode that uses syscalls as a comparison for your implementation.

Stealthy Process Hollowing: Update your process hollowing code (from Phase 3) to do things like PPID spoofing or to hollow out a less conspicuous process (e.g., svchost.exe). Measure its success by observing system behavior: Does the hollowed process appear legitimate in Task Manager? Does an EDR agent flag it? Tweak as needed (e.g., adjust memory permissions to match typical processes, so as not to flag Malicious Memory Protection features).

Red Team Tool Arsenal: Develop a couple of mini-tools focused on defense evasion:

A fileless execution tool: e.g., read an EXE from disk or network into memory and execute it without dropping to disk (a simple runPE or reflective loader).

A log cleaner: e.g., a tool that clears Windows Event Logs (use EventLog APIs) or disables Sysmon by stopping its service threads​
IRED.TEAM
(be careful testing this).

A covert data exfiltration script: maybe integrate a simple data theft (like reading files) with exfiltration over DNS or other channels (this is more networking, but you can attempt to encode data over multiple DNS queries as an evasion exercise).

Evasion Testing: Simulate “attacks” with your tools on a Windows 10/11 VM with Windows Defender enabled (and if possible, another AV or a trial of an EDR product). Use Defender’s Developer Mode to get detailed alerts. Observe which behaviors triggered detection (e.g., was it the memory injection, a suspicious API call, or a known malicious pattern?). Use this feedback to iterate: modify your code or technique and test again. This trial-and-error is invaluable for learning how real-world defenses respond. Keep notes on what works or not. (Always test in isolated environments to avoid any real damage.)

Recommended Resources:

Technical Blogs: The cybersecurity community actively shares EDR bypass research. Some must-reads: MDSec’s “Attacking Antivirus/EDR” blog series (they cover topics like DLL unhooking, AMSI bypass, and more), and posts on Countercept/FTS (Fidelity’s blog) about evasion. The ired.team site (Red Team Notes) has a whole section on Defense Evasion with practical examples (API unhooking, syscalls, process injection, PPID spoofing, etc.)​
IRED.TEAM
​
IRED.TEAM
. These are goldmines of techniques to learn and try.

Whitepapers & Talks: Check out conference talks like “Offensive Defense: evading EDRs” or BlackHat presentations on AV evasion. They often reveal how detection engines work internally, which helps you creatively bypass them. For instance, know that some EDRs have userland hooks (bypass via syscalls) while others monitor kernel events (bypass via misusing legitimate kernel interfaces). A standout reference is the book “Evading EDR: The Definitive Guide to Defeating Endpoint Detection Systems” by Matt Hand (No Starch Press, 2023) – it systematically covers modern EDR components and bypass strategies.

Tools & Code Repos: Explore the Awesome EDR Bypass GitHub repository​
GITHUB.COM
, which collects techniques and references. Examine open-source evasion tools:

SysWhispers2 and InlineWhispers (for direct syscalls and in-line assembly stubs).

Hell’s Gate and Halo’s Gate implementations (these are techniques to dynamically discover syscall numbers to avoid hard-coding them).

SharpBlock (C# tool that blocks API hooks by triggering AMSI/WD triggers intentionally) – while in C#, the concept can inspire C/C++ approaches.

PEzor or Donut for ideas on payload encryption and fileless execution.

Up-to-date Threat Research: Follow platforms like VX-Underground, MalwareBytes Labs, and Unit42 for the latest attacker techniques. For example, if a new APT tool is reported to use a novel injection or evasion method, dig into it. Incorporating cutting-edge tactics keeps your skills relevant. Many such reports include technical analysis that you can replicate in lab code.

Ethical and Safe Practice: Always remember, as you refine these techniques, handle them responsibly. Never test on networks or systems you don’t own. Keep your tools private – the more they’re shared, the more likely they’ll be flagged by defenses. Part of being a good red team developer is maintaining operational security of your tools.

Phase 5 (Weeks 17-20): Red Team Operations & Integration
Goals: Synthesize all your skills – C programming, Windows internals, payload dev, and evasion – to conduct end-to-end red team operations in a lab environment. This phase shifts focus from individual techniques to the orchestration of a full attack chain. You will practice using your custom tools in realistic scenarios: from initial compromise, through privilege escalation and lateral movement, to data exfiltration, all while remaining stealthy. Equally important, you’ll develop an eye for OpSec considerations: how to minimize footprints, avoid common mistakes, and detect when you’ve been caught. By operating with your tools, you’ll identify any gaps or stability issues to fix. The outcome is a refined skillset to emulate advanced threat actors on Windows environments.
Key Learning Topics:

Adversary Tactics & Kill Chain: Structure your practice around the MITRE ATT&CK tactics: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, and Impact. Map each phase of your operation to these categories and decide which custom tool/technique to use. For example, for Discovery: use your stealth enumeration tool to gather info on the host and domain (users, groups, software)​
MEDIUM.COM
​
IRED.TEAM
. For Credential Access: perhaps integrate Mimikatz-like functionality or use your injector to inject into LSASS (be careful with this) to dump hashes. Using ATT&CK as a framework ensures you cover all aspects of an engagement.

Operational Security (OpSec): Learn to think like a blue teamer to avoid tipping them off. Develop habits like: using covert communication channels (e.g., your C2 traffic over HTTPS with legitimate Host headers or domain fronting), time-based evasion (operate during night hours or blend with legitimate admin work times), and using failsafe killswitches (if the tool detects it’s being executed in an unauthorized environment or too long, it exits). Also, plan for error handling – e.g., if your exploit fails and crashes a service, how would that look to a SOC? You might implement a quick log clearing or have your payload restart the service to cover the crash.

Chaining and Automation: Write scripts (in Python or PowerShell) to coordinate your tools. For instance, a Python script that launches your initial dropper on a victim VM (simulating phishing), then sets up your listener for the reverse shell, then after connection, runs a series of post-exploitation tasks (perhaps using your compiled tools uploaded on the fly). This not only saves time during ops but also mimics frameworks like Cobalt Strike where multiple steps are automated.

Situational Awareness & Adaptation: Once inside the target (your lab machine/domain), use your tools to gather info quietly. For example, use your memory-only enumeration tool instead of running noisy commands. If you need to run a potentially noisy action, try to proxy it through a trusted process or use an allowed mechanism (this is where knowledge of LOLBins can help). If something fails (say your AV bypass doesn’t work on one host), have a backup plan (maybe use a different injection or a different payload that’s less flagged). This adaptability is key for real operations.

Reporting & Documentation: Although not directly technical, it’s useful to document your lab operations as if reporting to a client or team. Note each step, what worked, what was detected, and how you mitigated it. This helps solidify lessons learned and is a professional skill for real engagements. It will also highlight any gaps where you need to study more or develop another tool. For instance, you might realize you need a better way to move laterally – which prompts learning WMI or WinRM scripting in C# or using your C code to create Windows services remotely.

Hands-On Projects (Phase 5): (Simulate full attacks and fine-tune your toolkit in a controlled environment)

Lab Setup: Create a small Windows network lab. For example, one Windows Server acting as a Domain Controller, and two Windows 10 client VMs (one “employee” workstation, one file server). Ensure logging is enabled (Windows Event logs, maybe Sysmon if you’re ambitious). Optionally, install a trial of an EDR on one of the machines for a realistic challenge. This will be your playground to test a multi-stage attack.

Initial Compromise Simulation: Simulate phishing by delivering your payload to a workstation. This could be as simple as you manually executing the dropper on the VM, or you create a lure document with a macro that launches your payload (if you want to explore macro development – otherwise manual is fine). Once the payload runs, ensure you get a callback (reverse shell or beacon). Use that shell to establish persistence (e.g., run your registry persist tool from Phase 3). Verify persistence by rebooting the VM.

Post-Exploitation & Privilege Escalation: With a foothold, run your recon/enumeration tools. Gather local admin info, network shares, etc., covertly. If you’re not already admin, attempt a priv esc (you could use a known exploit or misconfiguration – since this is not the focus of development, you can use an off-the-shelf exploit or even a Meterpreter post module to simulate). Once admin/system, try dumping credentials: use your injection tool to inject a dumper into LSASS (if comfortable, or use an alternate like procdump and then analyze the dump with mimikatz on your system). The goal is to simulate credential theft.

Lateral Movement: Using credentials or hashes, move to the second machine or the DC. You can use your own tools (e.g., a custom service executer that uses Win32 CreateService to create a remote service launching your payload on the target) or leverage Windows utilities (psexec, WMI) if needed. Focus on staying stealthy: e.g., use your tool that executes commands via WMI but avoid writing any scripts to disk (use WMIC through your C2 channel). Establish a foothold on the next machine with your implant. Ensure your C2 can handle multiple sessions or run two instances of your listener.

Exfiltration: Imagine the target has sensitive data (say a file on the file server). Use your access to quietly gather and exfiltrate it. For example, compress it and split it, then use your C2 or a custom exfil tool to send it out (maybe your tool could even encode it in DNS queries or POST requests to a server you control). This project might involve writing a small client in C that reads a file and base64-encodes chunks to send over HTTP/DNS. Even if simplistic, it completes the picture of a full attack.

Detection Review: After the “engagement,” review logs on the target machines. See what was flagged: Were there Windows Event 4688 logs of suspicious process creations? Any antivirus alerts in Defender’s logs? Did your domain controller log any weird logon events? This will teach you what behaviors you couldn’t hide and allow you to brainstorm improvements. For instance, if your traffic was unencrypted HTTP, maybe use TLS next time; if your injected thread was detected, maybe try a different injection technique or sleep more.

Finalize Toolkit: Based on your experience, refine your tools and consolidate them. You might develop a simple menu-based tool that can perform multiple actions (a mini-agent), or at least package your various executables in a ready “toolkit” for use. Write README notes for each so you remember usage and OpSec considerations (e.g., “Tool X: injects shellcode – requires admin, avoid on highly monitored processes”).

Recommended Resources:

Frameworks & Emulation Guides: Review the MITRE ATT&CK framework for each tactic to ensure you have coverage or at least awareness of how to achieve it. The MITRE Adversary Emulation Plans (like APT3, APT29 plans that MITRE released) can be used as blueprints to test your tools against what real APT workflows look like. Also, consider reading the Red Team Operations training materials (e.g., Zero-Point Security’s CRTO course content if available) to learn how professionals structure their ops, though they use COTS tools, the concepts apply to your custom tool usage.

Case Studies: Read write-ups of real red team engagements or APT incident responses (many are available from FireEye Mandiant, Cisco Talos, etc.). These often detail how attackers moved, what tools/scripts they used, and how they were detected. For example, FireEye’s report on the compromise of their Red Team tools (the SolarWinds incident) described the tooling and techniques stolen​
PICUSSECURITY.COM
. This can validate if your toolset aligns with what real teams use, and might inspire new features.

Detection Engineering Blogs: Paradoxically, learning how defenders detect attacks will sharpen your offense. Follow blogs like Microsoft’s Detection Techniques or posts by the Blue Team (The Threat Hunter Playbook, Sigma rules repository). By seeing the detection logic (e.g., “alert on process injection into LSASS” or “flag any process using DbgBreakPoint API as likely unhooking attempt”), you can adjust your approach (maybe avoid LSASS or use a different API, etc.). This is the essence of red-team vs blue-team cat-and-mouse.

Community Engagement: At this stage, consider participating in community CTFs or labs that focus on red teaming (like Hack The Box Offshore or Cybernetics labs, or TryHackMe rooms on APT simulation). However, impose a rule on yourself: wherever possible, use your own tools instead of public ones. This will both test and improve your creations. You’ll quickly learn which of your tools are robust and which need work when put against live targets under time pressure.

Continuous Learning: The field of offensive security evolves rapidly. Allocate some of your 2-hour daily slots to read new research or try out a new tool. Perhaps dedicate “Techniques Tuesdays” to implement a new technique you read about, or “Firmware Fridays” to skim deeper topics like kernel exploits or hardware attacks (even if not directly used, they expand your perspective). With a strong base now, you can keep building on it.

Ethics and Professionalism: Finally, always ground your red team activities in ethics. In an org, custom tool development is a means to improve security by mimicking real threats. Document your tools well (for yourself and for possible peer review), handle them with care (to prevent abuse if they leaked), and ensure all usage in real engagements has proper authorization. This mindset will make you not just a skilled operator but a respected one.

Conclusion
Following this 20-week roadmap with 2 hours of daily deliberate practice will transform your skillset from theory-heavy to practically adept in Windows red team development. You will have built a strong C programming foundation, understood Windows internals in depth, created and refined malware-like tools, and learned to outsmart common defenses. Remember to continuously apply active learning techniques throughout – practice coding from memory, explain concepts in your own words, and regularly revisit older projects to reinforce knowledge. By structuring your learning with spaced repetition and hands-on projects, you dramatically accelerate your acquisition of complex skills​
ALGOCADEMY.COM
​FRONTIERSIN.ORG
. The journey is intense but highly rewarding: not only will you be able to craft stealthy implants and enumeration tools, but you’ll also think more like an adversary, which is the hallmark of an elite red teamer. Stay curious, keep experimenting, and never stop honing your craft – the security landscape will keep evolving, and you now have the roadmap to evolve with it. Good luck, and happy hacking!

Sources:
Research-backed learning techniques and up-to-date security blogs and resources were used to inform this roadmap. Key references include the importance of daily consistent practice​
ALGOCADEMY.COM
, active recall and spaced learning for programming​
ALGOCADEMY.COM
​ALGOCADEMY.COM
, the critical Windows internals concepts for maldev​
SYSTEMWEAKNESS.COM
, and specific red team tradecraft techniques from community knowledge bases​
IRED.TEAM
​PENTESTLABORATORIES.COM
, among others. Each phase’s guidance is grounded in expert content and real-world examples to ensure a practical, high-impact learning experience.

