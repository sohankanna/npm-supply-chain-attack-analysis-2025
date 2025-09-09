# Analysis of the September 2025 NPM Supply Chain Attack (`chalk`, `debug`)

> **⚠️ WARNING: MALICIOUS CODE ⚠️**
>
> The code in this repository is from a live malware campaign that targeted the NPM ecosystem. It is provided for **educational and security research purposes only**.
>
> **DO NOT EXECUTE THIS CODE** unless you are in a secure, sandboxed environment and fully understand the risks. Executing this code on a machine with a browser or network access could lead to the theft of your cryptocurrency and compromise your system. You have been warned.

## Executive Summary

This repository contains a detailed analysis and the deobfuscated source code for the crypto-stealing malware involved in the massive NPM supply chain attack on September 8, 2025. The attack compromised the account of a prolific maintainer, `qix`, leading to the publication of malicious versions of 18 popular packages, including `chalk` and `debug`, which are collectively downloaded over 2 billion times per week.

The payload was a sophisticated, client-side malware designed to steal cryptocurrency from the users of websites that bundled these compromised packages.

This analysis is a companion to my detailed article on Medium:
**[How One Phishing Email Injected Crypto-Stealing Malware into Billions of NPM Downloads](https://medium.com/@sohankanna/how-one-phishing-email-injected-crypto-stealing-malware-into-billions-of-npm-downloads-0aa0ecd2ae56)**

---

## Incident Timeline & Attack Vector

The attack was initiated through a well-executed social engineering campaign.

1.  **The Phish:** The package maintainer received a convincing phishing email from the fraudulent domain `support@npmjs.help`. The email claimed that their Two-Factor Authentication (2FA) credentials needed to be updated and created a sense of urgency by threatening account suspension.

2.  **Credential & 2FA Hijacking:** The link in the email led to a credential-harvesting page that cloned the look and feel of the official NPM website. The page prompted the user for their username, password, and their current 2FA token. By submitting this information in real-time, the attackers were able to capture the credentials and the valid, time-sensitive 2FA token, allowing them to bypass security and take full control of the maintainer's account.

3.  **Payload Deployment:** With account access, the attackers systematically published new, malicious patch versions for 18 packages. The change was a single, heavily obfuscated line of JavaScript injected into a core file of each package.

4.  **Detection & Response:** The malicious publications were quickly detected by automated security monitoring systems (like Aikido's) and the wider security community. The maintainer was notified and began the process of removing the malicious versions and securing their account.

---

## Malware Analysis

The malware is designed to be stealthy and efficient, activating only in a browser environment and targeting users of cryptocurrency wallets.

### Repository File Structure

*   **`deobfuscated_malware.js`**: The raw, deobfuscated malware script as produced by automated tools. This serves as the primary evidence.
*   **`annotated_malware.js`**: A version of the script with added comments and renamed variables to clarify its functionality and make it easier to understand.
*   **`README.md`**: This analysis file.

### Stage 1: Activation Logic

The script's first action is to determine if it's in a valuable environment. It does this by checking for the existence of `window.ethereum`, the global JavaScript object that browser wallets like MetaMask inject into websites.

```javascript
// The malware only activates its full potential if a Web3 wallet is detected.
if (typeof window !== 'undefined' && typeof window.ethereum !== 'undefined') {
  detectAndInitializeWalletHooks();
} else {
  // If no wallet is found, it falls back to only the network interception module.
  initializeAddressSwapper();
}
```
This check ensures that the most aggressive parts of the malware only run for active Web3 users, increasing the likelihood of a successful theft while reducing unnecessary noise.

### Stage 2: The Two-Pronged Attack

The malware deploys two distinct but complementary attack modules:

#### Module A: Passive Network Interception (`initializeAddressSwapper`)

This module is designed to alter what the user sees on a webpage. It hijacks the browser's native `fetch` and `XMLHttpRequest` functions, giving it the ability to inspect and modify all network traffic.

**Mechanism:**
1.  It intercepts the response body of network requests.
2.  It uses a series of regular expressions to find strings that match various cryptocurrency address formats (BTC, ETH, SOL, Tron, etc.).
3.  When it finds a legitimate address, it swaps it with an attacker's address from a hardcoded list of over 280 wallets.

The most sophisticated feature is its use of a **Levenshtein distance** algorithm to select the replacement address. It doesn't just pick a random wallet; it finds the attacker's address that is *most visually similar* to the original, making the malicious swap incredibly difficult for a user to spot on a webpage.

#### Module B: Active Transaction Hijacking (`hijackWalletTransactions`)

This is the malware's most direct theft mechanism. It hooks directly into the `window.ethereum` object, wrapping its core methods like `request`, `send`, and `sendAsync`. This allows it to intercept transaction data *before* it is sent to the user's wallet for signing.

**Mechanism:**
1.  It inspects the parameters of any outgoing transaction.
2.  For simple currency transfers (e.g., sending ETH), it replaces the `to` address with the attacker's wallet.
3.  For smart contract interactions, it inspects the `data` payload and looks for the function selectors of common token operations:
    *   `0xa9059cbb`: `transfer(address,uint256)`
    *   `0x23b872dd`: `transferFrom(address,address,uint256)`
    *   `0x095ea7b3`: `approve(address,uint256)`
4.  It then surgically replaces the legitimate recipient or spender address within the data payload with the attacker's hardcoded wallet address.

The user is then prompted by their wallet to sign a transaction that appears legitimate, but whose underlying data has been altered to steal their assets.

---

## Remediation for Developers

If your project depends on any of the compromised packages, you must take the following steps:

1.  **Identify:** Check your `package-lock.json` or `yarn.lock` file for the malicious versions listed in the Medium article.
2.  **Verify:** Run `grep -r 'checkethereumw' node_modules/` in your project's root directory to confirm if the malicious code is present in your installed dependencies.
3.  **Remediate:**
    *   Update the vulnerable packages in your `package.json` to the latest safe versions.
    *   Delete your `node_modules` directory and your lockfile (`package-lock.json` or `yarn.lock`).
    *   Run `npm install` or `yarn` to reinstall clean dependencies.
4.  **Secure:** Following the official advisory, assume any environment where the malicious package was installed has been compromised. **Rotate all secrets, API keys, and credentials** in your development and CI/CD environments.

---

## Indicators of Compromise (IoCs)

#### Domains
*   **Phishing Domain:** `npmjs.help`
*   **C2/Asset Domains:** `static-mw-host.b-cdn.net`, `img-data-backup.b-cdn.net`, `websocket-api2.publicvm.com`

#### IP Address
*   `185.7.81.108`

#### Primary Attacker Wallets
*   **Ethereum (ETH):** `0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976`
*   **Solana (SOL):** `19111111111111111111111111111111` (Junk address used to break transactions)

A full list of the 280+ hardcoded wallets used for address replacement can be found in the source code files in this repository.

---

## License

The analysis and annotations in this repository are licensed under the MIT License. See the `LICENSE` file for details. The malware itself is, of course, the property of its malicious authors.
