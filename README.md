# 🛡️ MI_GUARD: LangGraph Multi-Agent Security Firewall

An enterprise-grade, end-to-end multi-agent security architecture built with **LangGraph**, LangChain, Ollama, and Llama 3 (8B) to detect and block sophisticated prompt injection and jailbreak attacks in real-time.

## 🚀 Overview

As Large Language Models (LLMs) are deployed in production, they are increasingly vulnerable to prompt injections. 

This project implements a **Multi-Agent "Defense-in-Depth"** architecture. Utilizing a LangGraph state machine, it features a **Judge Agent** that intercepts user inputs *before* they reach the main application (the **Victim Agent**). The Judge rigorously analyzes the intent against strict security rules. If safe, the graph routes the prompt to the Victim Agent for an actual response; if malicious, the connection is structurally severed.

## ✨ Key Features
* **LangGraph State Orchestration:** Uses a production-ready state machine (`StateGraph`) to route state securely between the user, the Judge, and the Victim.
* **Agentic Firewall:** Uses Llama 3 (via Ollama) as a zero-trust security guardrail with zero access to system tools or data.
* **Red-Team Evaluation Pipeline:** Automated benchmarking script mimicking Microsoft PyRIT methodologies.
* **Sophisticated Threat Detection:** Capable of blocking:
  * Base64 Obfuscation & Encoding
  * Payload Splitting
  * Direct System Overrides ("Ignore previous instructions")
  * Persona Adoption & Roleplay ("Developer Mode", "DAN")
* **Local & Private:** Runs entirely locally on MacOS, ensuring zero data leakage to third-party APIs.

## 📁 Repository Structure
* `judge_agent.py`: The core LangGraph multi-agent workflow. Contains both the Judge Agent and Victim Agent, complete with a conditional state router.
* `evaluate_pyrit.py`: An automated test suite that processes datasets and calculates detection accuracy and latency.
* `generate_pyrit_dataset.py`: A procedural generator that creates diverse, 100-prompt threat datasets mimicking open-source PyRIT attacks.
* `jailbreaks_large.json`: A curated evaluation dataset of 100 benign and malicious prompts across 5 attack vectors.

## 📊 Evaluation Results

The Judge model was evaluated against a highly complex 100-prompt dataset containing nested logic traps, base64 payloads, and benign false-positive traps.
* **Model:** Meta Llama 3 (8B parameters)
* **Total Evaluated:** 100
* **Total Blocked / Correct:** 99
* **Accuracy Score:** **99.0%**

## 💻 How to Run

1. **Install Prerequisites:**
   Ensure you have Python 3 and [Ollama](https://ollama.com/) installed on your machine.
   ```bash
   pip3 install langchain langchain-community langgraph langchain-ollama
   ollama pull llama3
   ```

2. **Test the Judge Interactively:**
   ```bash
   python3 judge_agent.py
   ```
   *(Enter multi-line prompts to see how the Judge classifies them in real-time).*

3. **Run the Automated Threat Evaluation:**
   ```bash
   python3 evaluate_pyrit.py
   ```

## 🛠️ Tech Stack
* **Python 3**
* **LangChain** (LLM Orchestration)
* **Ollama** (Local Inference)
* **Meta Llama 3** (Security Evaluation Engine)


✨ Simple project to learn AI safety basics

Author: Avika 

B.Tech CSE (1st Year) | AI Safety & Security Research
