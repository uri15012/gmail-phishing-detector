# Gmail Malicious Email Scorer

**Author:** Uri Herszenhaut
**Date:** February 24th, 2026
**Project:** Gmail Malicious Email Scorer 

A Google Workspace Add-on for Gmail that analyzes incoming emails for phishing and malicious indicators, presenting a real-time threat score directly in the Gmail interface.

 It demonstrates the ability to integrate multiple external APIs, implement a multi-layered security model, and build a functional, user-facing application within the Google Workspace ecosystem using Google Apps Script.

**Note:** This README is structured in two parts. The first part is a high-level overview for evaluators and developers. The second part, "For the Tester," contains simple, step-by-step instructions for anyone testing the add-on.

## Table of Contents

*   [Project Overview](#project-overview)
*   [For the Tester: How to Install and Use](#for-the-tester-how-to-install-and-use)
*   [Scoring Model](#scoring-model)
*   [Architecture](#architecture)
*   [APIs Used](#apis-used)
*   [Limitations & Future Improvements](#limitations--future-improvements)

## Project Overview

This section provides a technical overview for developers and evaluators.

### Features

*   **Multi-Layered Threat Scoring:** Aggregates 9 distinct signals to produce a comprehensive threat score from 0 to 100.
*   **AI-Powered Content Analysis:** Uses the Google Gemini API to analyze email content for social engineering tactics, urgency, and manipulation.
*   **Real-Time Threat Intelligence:** Integrates with four leading cybersecurity APIs (VirusTotal, AbuseIPDB, IPQualityScore, Google Safe Browsing) to check domain, IP, URL, and email address reputation against live threat databases.
*   **Native Gmail UI:** Renders a clean, intuitive panel directly in the Gmail sidebar, providing an at-a-glance verdict and a detailed breakdown of all detected signals.
*   **User-Managed Blacklist:** Allows users to add or remove senders from a personal blacklist.
*   **Configurable Signals:** Users can enable or disable individual analysis signals from a settings panel.
*   **Scan History:** Keeps a log of the last 20 scanned emails for review.

### For the Developer: One-Time Setup

This project requires a one-time setup by the developer to function. Testers do not need to perform these steps.

1.  **API Keys:** The necessary API keys for Gemini, VirusTotal, AbuseIPDB, and IPQualityScore are stored in the `APIKeys.gs` file. The developer runs the `setApiKeys()` function once to save these keys securely in Google's `PropertiesService`. The add-on then uses these stored keys for all its operations.
2.  **Test Users:** For a tester to use the add-on, the developer must first add their Gmail address to the "Test users" list in the Google Cloud Console project under **APIs & Services > Audience**.

## For the Tester: How to Install and Use

Follow these steps to install and test the add-on. You do not need to worry about any API keys.

### Step 1: Install the Add-on

1.  The developer of this project has already added your Gmail account to the list of approved testers.
2.  Open the Apps Script project and click **Deploy > Test deployments**.
3.  A dialog will appear. Click the **Install** button.
4.  Click **Done**. The add-on is now ready to use in your Gmail.

### Step 2: Grant Permissions

The first time you use the add-on, Google will ask you to grant it permissions.

1.  A new window will open asking you to choose your Google account.
2.  On the next screen, you will see a list of permissions the add-on needs to run. Click **Allow** to approve them.

### Step 3: How to Use the Add-on

1.  Open any email in your Gmail inbox.
2.  The Gmail Malicious Email Scorer will automatically open in the right-hand sidebar.
3.  The add-on will analyze the email and show you a final verdict: **Safe**, **Suspicious**, or **Malicious**, along with a threat score and a list of all detected issues.

### Step 4: Explore the Management Console

At the bottom of the add-on, click the **Settings** button to open the Management Console. From here, you can:

*   **Manage Blacklist:** View, add, or remove senders from your personal block list.
*   **Toggle Signals On/Off:** Enable or disable different analysis features.
*   **View Scan History:** See a list of the last 20 emails you analyzed.
*   **Export Blacklist:** Copy your block list to save it as a backup.

## Scoring Model

The scoring model is a fixed-weight system where all signal weights sum to 100. The final score determines the verdict: **Safe** (0-30), **Suspicious** (31-60), or **Malicious** (61-100).

| Signal | Weight | Description |
| --- | --- | --- |
| Personal Blacklist | 20 | The sender is on the user's manually-managed blacklist. |
| VirusTotal Reputation | 15 | Sender domain or URLs are flagged by 70+ security engines. |
| Display Name Spoofing | 15 | The sender's name impersonates a known brand (e.g., "PayPal") but the domain does not match. |
| AbuseIPDB Reputation | 12 | The email's originating IP address has a high abuse confidence score from community reports. |
| Gemini AI Analysis | 10 | Google's Gemini model detects phishing language, urgency, or manipulation tactics. |
| Reply-To Mismatch | 10 | The Reply-To header points to a different domain than the sender, a classic phishing technique. |
| IPQualityScore Validation | 8 | The sender's email address is flagged as disposable, fraudulent, or from a recently created domain. |
| Suspicious Links | 7 | The email contains IP-based URLs, known URL shorteners, or excessively long URLs. |
| Google Safe Browsing | 3 | A URL in the email is on Google's official blacklist of malicious sites. |

## Architecture

The add-on is built entirely on Google Apps Script. The architecture is modular, with each core function separated into its own `.gs` file for clarity and maintainability.

1.  **Entry Point (`Code.gs`):** When a user opens an email, Gmail triggers the `buildAddOn()` function.
2.  **Email Parsing (`Code.gs`):** The `extractEmailData()` function parses the raw email, extracting headers, sender information, body content, and URLs.
3.  **Scoring Engine (`Code.gs`):** The `calculateScore()` function orchestrates the analysis, calling each signal function in sequence.
4.  **Signal Analysis (`.gs` files):** Each signal (e.g., `VirusTotal.gs`, `Gemini.gs`) is a self-contained module that takes email data, queries an external API, and returns a score contribution.
5.  **UI Rendering (`UI.gs`):** The final analysis object is passed to `buildVerdictCard()`, which uses Google's `CardService` to build and display the native UI card in the Gmail sidebar.

## APIs Used

| API | Purpose | Approx. Free Limit |
| --- | --- | --- |
| Google Gemini | AI-powered analysis of email content for social engineering. | Varies |
| VirusTotal | Reputation checks for domains and URLs. | 500 req/day |
| AbuseIPDB | Reputation checks for the email's originating IP address. | 1,000 req/day |
| IPQualityScore | Fraud and risk checks for the sender's email address. | ~5,000 req/month (est.) |
| Google Safe Browsing | Blacklist checks for URLs. | 10,000 req/day |

## Limitations & Future Improvements

*   **No SPF/DKIM/DMARC Validation:** The add-on does not validate SPF, DKIM, or DMARC — the three email authentication standards that verify whether an email was genuinely sent from its claimed server. Implementing this would require DNS lookup capabilities that are not natively available in Google Apps Script. In a production system, this would be a critical layer of defense.
*   **Limited Header Analysis:** The add-on reads only the most common email headers (From, Reply-To, Received). A more complete analysis would trace the full server routing chain in the headers to detect anomalies, such as an email claiming to come from a US company but routed through servers in another country.
*   **No Attachment Scanning:** The add-on does not scan email attachments. File-based attacks, like malicious PDFs or Word documents, are a common phishing vector that this version does not cover. Implementing this would require uploading attachments to a sandbox scanning API (such as VirusTotal's file endpoint), which is a significant extension beyond the current scope.
*   **Static Brand List for Spoofing:** The display name spoofing detection relies on a hardcoded list of 14 commonly impersonated brands. Any brand not on this list will not trigger the signal. A future improvement would replace this with a dynamic brand intelligence API capable of recognizing thousands of organizations.

---

Thank you for taking the time to review this project.
