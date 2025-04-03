# SAML SSO Helper Tool

A simple, client-side web application built with HTML, CSS, and JavaScript designed to assist developers, system administrators, and support engineers in debugging and understanding SAML 2.0 Single Sign-On (SSO) flows and related components like X.509 certificates.

All processing happens **directly in your browser**, ensuring that sensitive data like SAML assertions or private keys (potentially embedded in certificates if pasted carelessly) never leave your machine.

https://luigidefacci.github.io/SAML-SSO-Helper-Tool/

## Key Features

*   **SAML Message Analyzer:**
    *   Decodes Base64 encoded SAML messages.
    *   Accepts raw XML input for SAML Responses, AuthnRequests, and LogoutRequests.
    *   Pretty-prints the XML for readability.
    *   Extracts key information: Issuer, Status, Destination, Subject NameID & Format, Conditions (NotBefore/NotOnOrAfter), Audience, Signatures (presence only), AuthnInstant, SessionIndex, and more.
    *   Checks and highlights the current validity of Assertion Conditions based on your system clock.
*   **X.509 Certificate Analyzer:**
    *   Parses PEM-formatted X.509 certificates (including `-----BEGIN/END CERTIFICATE-----` lines).
    *   Displays crucial details: Subject, Issuer, Validity Period (Not Before/Not After), Serial Number, Signature Algorithm, Version, and Public Key info (Type/Size).
    *   Clearly indicates if the certificate is currently **valid**, **expired**, or **not yet valid** based on your system clock.
*   **Base64 Encoder/Decoder:** Simple tool for Base64 encoding/decoding text (UTF-8 safe).
*   **URL Encoder/Decoder:** Utility for percent-encoding and decoding URL components.
*   **Client-Side Processing:** All operations run entirely within the user's browser using JavaScript. No data is sent to any external server.

## How to Use

1.  Clone this repository or download the files (`index.html`, `style.css`, `script.js`).
2.  Open the `index.html` file directly in your web browser (e.g., Chrome, Firefox, Edge). **No web server or installation is required.**
3.  Navigate to the tool section you need (SAML Analyzer, Certificate Analyzer, etc.).
4.  Paste your data into the appropriate text area:
    *   For SAML Analyzer: Use Base64 input or Raw XML input.
    *   For Certificate Analyzer: Paste the full PEM certificate content.
    *   For Utilities: Paste the text to be encoded/decoded.
5.  Click the corresponding "Analyze", "Decode", or "Encode" button.
6.  View the formatted output and analysis results in the designated areas below the inputs.

## Technology Stack

*   HTML5
*   CSS3
*   Vanilla JavaScript (ES6+)
*   [jsrsasign](https://github.com/kjur/jsrsasign) (for X.509 certificate parsing via CDN)

## Important Considerations & Limitations

*   ⚠️ **NO SIGNATURE VERIFICATION:** This tool **DOES NOT** perform cryptographic signature validation on SAML messages or certificates. It only checks for the *presence* of a `<ds:Signature>` element. **Do not rely on this tool for security validation.** Verifying signatures correctly requires managing trust anchors (trusted public keys/certificates) which is complex and potentially insecure to handle entirely client-side without proper user configuration.
*   **Client-Side Operation:** All processing relies on the user's browser capabilities and system clock for date comparisons.
*   **Debugging Focus:** This tool is intended as a helper for debugging, troubleshooting, and understanding SAML structures and certificate details, not as a production validation endpoint.
*   **XML/PEM Formatting:** Assumes reasonably well-formatted input. Highly malformed data or unexpected structures might lead to parsing errors or incomplete analysis.

## Contributing

Contributions are welcome! Feel free to open an issue to report bugs or suggest features, or submit a pull request with improvements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
*(You should create a file named `LICENSE` and add the MIT License text to it)*
