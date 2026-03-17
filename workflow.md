MI_GUARD – Prompt Injection Defense System  
Simple Workflow Document (Beginner-Friendly)

--------------------------------------------------

PROJECT OVERVIEW

MI_GUARD is a simple system that protects an AI from harmful or trick inputs (prompt injection).

Problem it solves:
- AI agents can be tricked by malicious instructions  
- This system checks input before execution and blocks unsafe prompts  

--------------------------------------------------

TOOLS & TECHNOLOGIES USED

• Python  
  - What: Programming language  
  - Why: Easy and beginner-friendly  
  - How: Used to build agent, judge, and middleware logic  

• VS Code  
  - What: Code editor  
  - Why: Simple and widely used  
  - How: Write and run all project files  

• Ollama  
  - What: Tool to run AI models locally  
  - Why: No cost, works offline  
  - How: Runs the Phi-3 model on your system  

• Microsoft Phi-3  
  - What: Lightweight AI model  
  - Why: Used as a smart security checker  
  - How: Acts as the “Judge” to detect malicious input  

• LangChain (Optional)  
  - What: Tool to organize AI workflows  
  - Why: Makes agent structure cleaner  
  - How: Can be used to connect model + logic (optional use)  

• Microsoft PyRIT  
  - What: Testing tool for AI security  
  - Why: Helps test prompt injection attacks  
  - How: Sends multiple attack prompts to check system strength  

• HTML / CSS / JavaScript  
  - What: Web technologies  
  - Why: Build a simple user interface  
  - How: Create input box and display results  

• GitHub  
  - What: Code hosting platform  
  - Why: Share and manage project  
  - How: Upload code and track changes  

--------------------------------------------------

STEP-BY-STEP WORKFLOW

STEP 1: Build Victim Agent

What it does:
- Takes user input  
- Executes it directly  
- No safety check  

How to build:
- Use Python  
- Create a simple function  
- Input → Response  

Purpose:
- Shows how AI can be easily tricked  

--------------------------------------------------

STEP 2: Build Judge using Phi-3 (via Ollama)

What it does:
- Checks if input is safe or malicious  

How it works:
- Run Phi-3 locally using Ollama  
- Send user input to the model  
- Model returns:
  CLEAN or MALICIOUS  

Purpose:
- Acts as a smart security layer  

--------------------------------------------------

STEP 3: Build Middleware (Python)

What it does:
- Connects user → judge → agent  

How it works:
1. Take user input  
2. Send to Judge (Phi-3)  
3. Get result  

Decision:
- If CLEAN → send to agent  
- If MALICIOUS → block input  

Output:
- Show response OR warning message  

--------------------------------------------------

STEP 4: Testing using PyRIT

What it does:
- Tests system with many attack prompts  

How to use:
- Send different malicious inputs  
- Check how many are blocked  

Purpose:
- Measure how secure the system is  

--------------------------------------------------

STEP 5: Create Web Demo

What it does:
- Shows system in browser  

How to build:
- HTML → input box  
- CSS → simple design  
- JavaScript → handle interaction  

Features:
- User enters input  
- Show:
  - CLEAN or MALICIOUS  
  - Response or Block message  

--------------------------------------------------

SIMPLE FLOW DIAGRAM

User Input → Judge (Phi-3 via Ollama)  
→ CLEAN → Victim Agent  
→ MALICIOUS → Block  

--------------------------------------------------

FINAL OUTPUT

The project will demonstrate:

• How AI behaves without security  
• How MI_GUARD blocks malicious inputs  
• A simple AI safety system  

Learning outcome:

- Understand prompt injection  
- Learn basic AI security  
- Build a real working demo  

--------------------------------------------------

SUMMARY

• Build a vulnerable AI (Agent)  
• Add a smart Judge using Phi-3  
• Connect using Middleware  
• Test using PyRIT  
• Show results using CLI or Web  

--------------------------------------------------

Simple, practical, and impressive project for learning AI security
