document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    // SAML
    const samlResponseInput = document.getElementById('samlResponseInput');
    const analyzeSamlBtn = document.getElementById('analyzeSamlBtn');
    const samlRawXmlInput = document.getElementById('samlRawXmlInput');
    const analyzeRawXmlBtn = document.getElementById('analyzeRawXmlBtn');
    const samlXmlOutput = document.getElementById('samlXmlOutput');
    const samlAnalysisOutput = document.getElementById('samlAnalysisOutput');

    // Certificate
    const certificateInput = document.getElementById('certificateInput');
    const analyzeCertBtn = document.getElementById('analyzeCertBtn');
    const certAnalysisOutput = document.getElementById('certAnalysisOutput');

    // Base64
    const base64Input = document.getElementById('base64Input');
    const base64EncodeBtn = document.getElementById('base64EncodeBtn');
    const base64DecodeBtn = document.getElementById('base64DecodeBtn');
    const base64Output = document.getElementById('base64Output');

    // URL
    const urlInput = document.getElementById('urlInput');
    const urlEncodeBtn = document.getElementById('urlEncodeBtn');
    const urlDecodeBtn = document.getElementById('urlDecodeBtn');
    const urlOutput = document.getElementById('urlOutput');

    // --- Constants ---
    const SAML_NS = {
        samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
        saml: "urn:oasis:names:tc:SAML:2.0:assertion",
        ds: "http://www.w3.org/2000/09/xmldsig#"
    };

    // --- Helper Functions ---
    function displayError(element, message) {
        element.innerHTML = `<div class="error">Error: ${message}</div>`;
    }

    function clearOutput(...elements) {
        elements.forEach(el => {
            if (el) {
                if (el.nodeName === 'PRE' || el.nodeName === 'TEXTAREA') {
                    el.textContent = ''; // Use textContent for pre/textarea
                } else if (el.innerHTML !== undefined) {
                    el.innerHTML = ''; // Use innerHTML for divs
                }
            }
        });
    }


    function formatXml(xmlString) {
        try {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlString, "application/xml");

            const parserError = xmlDoc.querySelector("parsererror");
            if (parserError) {
                console.error("XML Parsing Error:", parserError.textContent);
                 // Just return the original string if it's not valid XML for formatting
                return `Invalid XML (cannot format):\n${parserError.textContent}\n\nOriginal XML:\n${xmlString}`;
            }

            // Basic indentation fallback if XSLT fails or isn't desired
            let formatted = '';
            let indent = '';
            xmlString.split(/>\s*</).forEach(node => {
                if (node.match(/^\/\w/)) indent = indent.substring(2); // Decrease indent for closing tag
                formatted += indent + '<' + node + '>\n';
                if (node.match(/^<?\w[^>]*[^\/]$/)) indent += '  '; // Increase indent for opening tag
            });
             // Trim the final newline and the initial '<'
             formatted = formatted.substring(1, formatted.length - 1).trim();

             // Basic heuristic check if formatting actually looks like XML
             if (formatted.startsWith('<') && formatted.endsWith('>')) {
                 return formatted;
             } else {
                 // If formatting failed badly, return original
                 console.warn("Basic XML formatting resulted in non-XML output, returning original.");
                 return xmlString;
             }

        } catch (e) {
            console.error("Error formatting XML:", e);
            return `Could not format XML. Error: ${e.message}\n\nOriginal XML:\n${xmlString}`;
        }
    }


    // --- Reusable SAML Analysis Function ---
    function analyzeSamlXml(xmlString) {
        clearOutput(samlXmlOutput, samlAnalysisOutput); // Clear previous results

        samlXmlOutput.textContent = formatXml(xmlString);

        try {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlString, "application/xml");

            const parserError = xmlDoc.querySelector("parsererror");
            if (parserError) {
                displayError(samlAnalysisOutput, `Invalid XML structure. Cannot analyze. Details: ${parserError.textContent}`);
                return;
            }

            let analysisHtml = '';

            // --- Identify Root Element ---
            const responseEl = xmlDoc.getElementsByTagNameNS(SAML_NS.samlp, 'Response')[0];
            const logoutRequestEl = xmlDoc.getElementsByTagNameNS(SAML_NS.samlp, 'LogoutRequest')[0];
            const authnRequestEl = xmlDoc.getElementsByTagNameNS(SAML_NS.samlp, 'AuthnRequest')[0];

            if (responseEl) {
                // --- Analyze SAML Response ---
                analysisHtml += `<div><span class="label">Detected Type:</span> SAML Response</div>`;

                // Status
                const statusEl = responseEl.getElementsByTagNameNS(SAML_NS.samlp, 'Status')[0];
                if (statusEl) {
                    const statusCodeEl = statusEl.getElementsByTagNameNS(SAML_NS.samlp, 'StatusCode')[0];
                    const statusCodeValue = statusCodeEl?.getAttribute('Value'); // Use optional chaining
                    analysisHtml += `<div><span class="label">Status Code:</span> ${statusCodeValue || 'Not Found'} `;
                    if (statusCodeValue === 'urn:oasis:names:tc:SAML:2.0:status:Success') {
                        analysisHtml += `(<span class="status-valid">Success</span>)`;
                    } else {
                        analysisHtml += `(<span class="status-invalid">Not Success</span>)`;
                    }
                    analysisHtml += `</div>`; // Close status code div

                    const statusMessageEl = statusEl.getElementsByTagNameNS(SAML_NS.samlp, 'StatusMessage')[0];
                    if (statusMessageEl && statusMessageEl.textContent) {
                         analysisHtml += `<div><span class="label">Status Message:</span> ${statusMessageEl.textContent}</div>`;
                    }
                } else {
                     analysisHtml += `<div><span class="label">Status:</span> <span class="status-warning">Status element not found</span></div>`;
                }

                // Issuer (Check Response level first, might override Assertion's)
                const responseIssuerEl = responseEl.getElementsByTagNameNS(SAML_NS.saml, 'Issuer')[0];
                const responseIssuerValue = responseIssuerEl?.textContent;
                if (responseIssuerValue) {
                     analysisHtml += `<div><span class="label">Issuer (Response):</span> ${responseIssuerValue}</div>`;
                }

                // Destination
                const destination = responseEl.getAttribute('Destination');
                analysisHtml += `<div><span class="label">Destination:</span> ${destination || 'Not Specified'}</div>`;

                // InResponseTo
                const inResponseTo = responseEl.getAttribute('InResponseTo');
                analysisHtml += `<div><span class="label">InResponseTo:</span> ${inResponseTo || 'Not Specified'}</div>`;

                // Issue Instant (Response)
                analysisHtml += `<div><span class="label">Issue Instant (Response):</span> ${responseEl.getAttribute('IssueInstant') || 'Not Found'}</div>`;

                // Response Signature
                 const responseSignatureEl = responseEl.getElementsByTagNameNS(SAML_NS.ds, 'Signature')[0];
                 // Note: Need specific check because getElementsByTagNameNS could return signature from Assertion if not careful
                 let directResponseSignature = null;
                 for (let i = 0; i < responseEl.childNodes.length; i++) {
                     const child = responseEl.childNodes[i];
                     if (child.namespaceURI === SAML_NS.ds && child.localName === 'Signature') {
                         directResponseSignature = child;
                         break;
                     }
                 }
                 analysisHtml += `<div><span class="label">Signature (Response Level):</span> ${directResponseSignature ? '<span class="status-valid">Present</span>' : '<span class="status-warning">Not Found</span>'}</div>`;


                // --- Analyze Assertion (if present) ---
                const assertionEl = responseEl.getElementsByTagNameNS(SAML_NS.saml, 'Assertion')[0];
                if (assertionEl) {
                     analysisHtml += `<hr><div style="font-weight: bold; margin-top: 10px;">Assertion Details:</div>`; // Separator

                     // Issuer (Assertion)
                     const assertionIssuerEl = assertionEl.getElementsByTagNameNS(SAML_NS.saml, 'Issuer')[0];
                     analysisHtml += `<div><span class="label">Issuer (Assertion):</span> ${assertionIssuerEl?.textContent || 'Not Found'}</div>`;

                     // Assertion ID
                     analysisHtml += `<div><span class="label">Assertion ID:</span> ${assertionEl.getAttribute('ID') || 'Not Found'}</div>`;

                     // Issue Instant (Assertion)
                     analysisHtml += `<div><span class="label">Issue Instant (Assertion):</span> ${assertionEl.getAttribute('IssueInstant') || 'Not Found'}</div>`;

                     // Subject and NameID
                     const subjectEl = assertionEl.getElementsByTagNameNS(SAML_NS.saml, 'Subject')[0];
                     if (subjectEl) {
                         const nameIdEl = subjectEl.getElementsByTagNameNS(SAML_NS.saml, 'NameID')[0];
                         if (nameIdEl) {
                             const nameIDValue = nameIdEl.textContent || '[Empty Tag]';
                             const nameIDFormatValue = nameIdEl.getAttribute('Format') || 'Not Specified';
                             analysisHtml += `<div><span class="label">Subject NameID:</span> ${nameIDValue}</div>`;
                             analysisHtml += `<div><span class="label">NameID Format:</span> ${nameIDFormatValue}</div>`;
                         } else {
                             analysisHtml += `<div><span class="label">Subject NameID:</span> <span class="status-warning">Not Found (Element missing in Subject)</span></div>`;
                             analysisHtml += `<div><span class="label">NameID Format:</span> <span class="status-warning">N/A (No NameID Element)</span></div>`;
                         }

                         // Add Subject Confirmation Data (Basic)
                         const subjConfEl = subjectEl.getElementsByTagNameNS(SAML_NS.saml, 'SubjectConfirmation')[0];
                         const subjConfDataEl = subjConfEl?.getElementsByTagNameNS(SAML_NS.saml, 'SubjectConfirmationData')[0];
                         if (subjConfDataEl) {
                              analysisHtml += `<div><span class="label">SubjectConfirmation Method:</span> ${subjConfEl.getAttribute('Method') || 'Not Specified'}</div>`;
                              analysisHtml += `<div><span class="label">SubjectConf Recipient:</span> ${subjConfDataEl.getAttribute('Recipient') || 'Not Found'}</div>`;
                              analysisHtml += `<div><span class="label">SubjectConf NotOnOrAfter:</span> ${subjConfDataEl.getAttribute('NotOnOrAfter') || 'Not Found'}</div>`;
                         }

                     } else {
                         analysisHtml += `<div><span class="label">Subject:</span> <span class="status-warning">Subject element not found in Assertion</span></div>`;
                         analysisHtml += `<div><span class="label">Subject NameID:</span> <span class="status-warning">N/A (No Subject Element)</span></div>`;
                     }

                     // Conditions
                     const conditionsEl = assertionEl.getElementsByTagNameNS(SAML_NS.saml, 'Conditions')[0];
                     if (conditionsEl) {
                         const notBefore = conditionsEl.getAttribute('NotBefore');
                         const notOnOrAfter = conditionsEl.getAttribute('NotOnOrAfter');
                         analysisHtml += `<div><span class="label">Conditions NotBefore:</span> ${notBefore || 'Not Found'}</div>`;
                         analysisHtml += `<div><span class="label">Conditions NotOnOrAfter:</span> ${notOnOrAfter || 'Not Found'}</div>`;

                         if (notBefore && notOnOrAfter) {
                             const now = new Date();
                             try { // Add try-catch for date parsing robustness
                                const notBeforeDate = new Date(notBefore);
                                const notOnOrAfterDate = new Date(notOnOrAfter);
                                let validityStatus = '';
                                if (isNaN(notBeforeDate.getTime()) || isNaN(notOnOrAfterDate.getTime())) {
                                    validityStatus = `<span class="status-warning">Invalid date format</span>`;
                                } else if (now < notBeforeDate) {
                                    validityStatus = `<span class="status-not-yet-valid">Not Yet Valid</span>`;
                                } else if (now >= notOnOrAfterDate) {
                                    validityStatus = `<span class="status-expired">Expired</span>`;
                                } else {
                                    validityStatus = `<span class="status-valid">Currently Valid</span>`;
                                }
                                analysisHtml += `<div><span class="label">Validity Period:</span> ${validityStatus}</div>`;
                            } catch (dateError) {
                                 analysisHtml += `<div><span class="label">Validity Period:</span> <span class="status-warning">Error parsing dates (${dateError.message})</span></div>`;
                            }
                         } else {
                             analysisHtml += `<div><span class="label">Validity Period:</span> <span class="status-warning">Missing NotBefore or NotOnOrAfter</span></div>`;
                         }

                         // Audience Restriction
                         const audienceRestrictionEls = conditionsEl.getElementsByTagNameNS(SAML_NS.saml, 'AudienceRestriction');
                         let allAudiences = [];
                         if (audienceRestrictionEls.length > 0) {
                            for (let restriction of audienceRestrictionEls) {
                                const audienceElements = restriction.getElementsByTagNameNS(SAML_NS.saml, 'Audience');
                                for (let aud of audienceElements) {
                                    if(aud.textContent) allAudiences.push(aud.textContent);
                                }
                            }
                         }
                          analysisHtml += `<div><span class="label">Audience(s):</span> ${allAudiences.length > 0 ? allAudiences.join(', ') : '<span class="status-warning">Not Found in Conditions</span>'}</div>`;

                     } else {
                         analysisHtml += `<div><span class="label">Conditions:</span> <span class="status-warning">Conditions element not found in Assertion</span></div>`;
                         analysisHtml += `<div><span class="label">Audience(s):</span> <span class="status-warning">N/A (No Conditions)</span></div>`;
                     }

                     // AuthnStatement (Basic Info)
                      const authnStatementEl = assertionEl.getElementsByTagNameNS(SAML_NS.saml, 'AuthnStatement')[0];
                      if (authnStatementEl) {
                           analysisHtml += `<div><span class="label">AuthnInstant:</span> ${authnStatementEl.getAttribute('AuthnInstant') || 'Not Found'}</div>`;
                           analysisHtml += `<div><span class="label">SessionIndex:</span> ${authnStatementEl.getAttribute('SessionIndex') || 'Not Specified'}</div>`;
                           const authnContextClassRefEl = authnStatementEl.getElementsByTagNameNS(SAML_NS.saml, 'AuthnContextClassRef')[0];
                           analysisHtml += `<div><span class="label">AuthnContextClassRef:</span> ${authnContextClassRefEl?.textContent || 'Not Found'}</div>`;
                      }

                      // AttributeStatement (Count Attributes)
                      const attributeStatementEl = assertionEl.getElementsByTagNameNS(SAML_NS.saml, 'AttributeStatement')[0];
                      if (attributeStatementEl) {
                           const attributes = attributeStatementEl.getElementsByTagNameNS(SAML_NS.saml, 'Attribute');
                           analysisHtml += `<div><span class="label">Attributes Found:</span> ${attributes.length}</div>`;
                           // Could add loop here later to display attribute names/values if desired
                      } else {
                           analysisHtml += `<div><span class="label">Attributes Found:</span> 0 (No AttributeStatement)</div>`;
                      }


                     // Assertion Signature
                     const assertionSignatureEl = assertionEl.getElementsByTagNameNS(SAML_NS.ds, 'Signature')[0];
                     let directAssertionSignature = null;
                      for (let i = 0; i < assertionEl.childNodes.length; i++) {
                         const child = assertionEl.childNodes[i];
                         if (child.namespaceURI === SAML_NS.ds && child.localName === 'Signature') {
                             directAssertionSignature = child;
                             break;
                         }
                      }
                     analysisHtml += `<div><span class="label">Signature (Assertion Level):</span> ${directAssertionSignature ? '<span class="status-valid">Present</span>' : '<span class="status-warning">Not Found</span>'}</div>`;

                } else {
                    analysisHtml += `<hr><div class="status-warning" style="margin-top: 10px;">No Assertion element found in the Response.</div>`;
                }

            } else if (logoutRequestEl) {
                // --- Analyze LogoutRequest ---
                analysisHtml += `<div><span class="label">Detected Type:</span> <span class="status-warning">LogoutRequest (Basic analysis)</span></div>`;
                const issuerEl = logoutRequestEl.getElementsByTagNameNS(SAML_NS.saml, 'Issuer')[0];
                const nameIdEl = logoutRequestEl.getElementsByTagNameNS(SAML_NS.saml, 'NameID')[0];
                analysisHtml += `<div><span class="label">Issuer:</span> ${issuerEl?.textContent || 'Not Found'}</div>`;
                if (nameIdEl) {
                     analysisHtml += `<div><span class="label">NameID:</span> ${nameIdEl.textContent || '[Empty]'}</div>`;
                     analysisHtml += `<div><span class="label">NameID Format:</span> ${nameIdEl.getAttribute('Format') || 'Not Specified'}</div>`;
                 } else {
                     analysisHtml += `<div><span class="label">NameID:</span> <span class="status-warning">Not Found</span></div>`;
                 }
                analysisHtml += `<div><span class="label">ID:</span> ${logoutRequestEl.getAttribute('ID') || 'Not Found'}</div>`;
                analysisHtml += `<div><span class="label">Destination:</span> ${logoutRequestEl.getAttribute('Destination') || 'Not Found'}</div>`;
                analysisHtml += `<div><span class="label">IssueInstant:</span> ${logoutRequestEl.getAttribute('IssueInstant') || 'Not Found'}</div>`;
                analysisHtml += `<div><span class="label">SessionIndex:</span> ${logoutRequestEl.getElementsByTagNameNS(SAML_NS.samlp, 'SessionIndex')[0]?.textContent || 'Not Found'}</div>`;

            } else if (authnRequestEl) {
                // --- Analyze AuthnRequest ---
                 analysisHtml += `<div><span class="label">Detected Type:</span> <span class="status-warning">AuthnRequest (Basic analysis)</span></div>`;
                 const issuerEl = authnRequestEl.getElementsByTagNameNS(SAML_NS.saml, 'Issuer')[0];
                 const subjectEl = authnRequestEl.getElementsByTagNameNS(SAML_NS.saml, 'Subject')[0];
                 const nameIdPolicyEl = authnRequestEl.getElementsByTagNameNS(SAML_NS.samlp, 'NameIDPolicy')[0];
                 analysisHtml += `<div><span class="label">Issuer:</span> ${issuerEl?.textContent || 'Not Found'}</div>`;
                  if (subjectEl) {
                      const nameIdEl = subjectEl.getElementsByTagNameNS(SAML_NS.saml, 'NameID')[0];
                      if (nameIdEl) {
                           analysisHtml += `<div><span class="label">Subject NameID Hint:</span> ${nameIdEl.textContent || '[Empty]'}</div>`;
                       }
                  }
                  if (nameIdPolicyEl) {
                      analysisHtml += `<div><span class="label">Requested NameIDPolicy Format:</span> ${nameIdPolicyEl.getAttribute('Format') || 'Not Specified'}</div>`;
                      analysisHtml += `<div><span class="label">AllowCreate:</span> ${nameIdPolicyEl.getAttribute('AllowCreate') || 'Not Specified'}</div>`;
                  } else {
                       analysisHtml += `<div><span class="label">NameIDPolicy:</span> <span class="status-warning">Not Found</span></div>`;
                  }
                 analysisHtml += `<div><span class="label">ID:</span> ${authnRequestEl.getAttribute('ID') || 'Not Found'}</div>`;
                 analysisHtml += `<div><span class="label">Destination:</span> ${authnRequestEl.getAttribute('Destination') || 'Not Found'}</div>`;
                 analysisHtml += `<div><span class="label">AssertionConsumerServiceURL:</span> ${authnRequestEl.getAttribute('AssertionConsumerServiceURL') || 'Not Found'}</div>`;
                 analysisHtml += `<div><span class="label">ProtocolBinding:</span> ${authnRequestEl.getAttribute('ProtocolBinding') || 'Not Found'}</div>`;
                 analysisHtml += `<div><span class="label">IssueInstant:</span> ${authnRequestEl.getAttribute('IssueInstant') || 'Not Found'}</div>`;

            } else {
                analysisHtml += `<div class="error">Could not find a recognizable SAML root element (<samlp:Response>, <samlp:LogoutRequest>, or <samlp:AuthnRequest>). Please check the XML structure and namespaces.</div>`;
            }

            // --- Display Final Results ---
            samlAnalysisOutput.innerHTML = analysisHtml;

        } catch (e) {
            console.error("Error during SAML analysis:", e);
            displayError(samlAnalysisOutput, `Failed to parse or analyze XML. ${e.message}`);
            samlXmlOutput.textContent = xmlString; // Show original XML on error
        }
    } // --- End of analyzeSamlXml ---


    // --- Event Listeners ---

    // Analyze Base64 Button
    analyzeSamlBtn.addEventListener('click', () => {
        clearOutput(samlXmlOutput, samlAnalysisOutput);
        const base64InputVal = samlResponseInput.value.trim();
        if (!base64InputVal) {
            displayError(samlAnalysisOutput, "Base64 input cannot be empty.");
            return;
        }
        let xmlString;
        try {
            samlRawXmlInput.value = ''; // Clear other input
            xmlString = atob(base64InputVal);
        } catch (e) {
            displayError(samlAnalysisOutput, "Invalid Base64 input.");
            samlXmlOutput.textContent = "Input does not appear to be valid Base64.";
            return;
        }
        analyzeSamlXml(xmlString); // Call the main analysis function
    });

    // Analyze Raw XML Button
    analyzeRawXmlBtn.addEventListener('click', () => {
        clearOutput(samlXmlOutput, samlAnalysisOutput);
        const rawXmlInputVal = samlRawXmlInput.value.trim();
        if (!rawXmlInputVal) {
            displayError(samlAnalysisOutput, "Raw XML input cannot be empty.");
            return;
        }
        samlResponseInput.value = ''; // Clear other input
        analyzeSamlXml(rawXmlInputVal); // Call the main analysis function
    });


    // --- Certificate Analyzer Logic ---
    analyzeCertBtn.addEventListener('click', () => {
        clearOutput(certAnalysisOutput);
        const pemInput = certificateInput.value.trim();
        if (!pemInput) {
            displayError(certAnalysisOutput, "Certificate input cannot be empty.");
            return;
        }
        if (!pemInput.startsWith('-----BEGIN CERTIFICATE-----') || !pemInput.includes('-----END CERTIFICATE-----')) { // Check includes for flexibility
             displayError(certAnalysisOutput, "Input does not look like a valid PEM certificate. Ensure it includes the BEGIN/END CERTIFICATE lines.");
             return;
        }

        try {
            const cert = new jsrsasign.X509();
            cert.readCertPEM(pemInput); // jsrsasign handles potential extra whitespace/newlines

            const subject = cert.getSubjectString().replace(/\//g, ', '); // Cleaner display
            const issuer = cert.getIssuerString().replace(/\//g, ', ');
            const notBeforeRaw = cert.getNotBefore();
            const notAfterRaw = cert.getNotAfter();

            const parseDate = (dateStr) => {
                 let year = parseInt(dateStr.substring(0, 2), 10);
                 year += (year < 70) ? 2000 : 1900; // Updated Y2K heuristic (adjust if needed)
                 const month = parseInt(dateStr.substring(2, 4), 10) - 1;
                 const day = parseInt(dateStr.substring(4, 6), 10);
                 const hour = parseInt(dateStr.substring(6, 8), 10);
                 const minute = parseInt(dateStr.substring(8, 10), 10);
                 const second = parseInt(dateStr.substring(10, 12), 10);
                 return new Date(Date.UTC(year, month, day, hour, minute, second));
            };

            const notBeforeDate = parseDate(notBeforeRaw);
            const notAfterDate = parseDate(notAfterRaw);
            const now = new Date();

             let validityStatus = '';
             let validityClass = 'status-warning'; // Default class

             if (isNaN(notBeforeDate.getTime()) || isNaN(notAfterDate.getTime())) {
                 validityStatus = `Invalid date format in certificate (${notBeforeRaw} / ${notAfterRaw})`;
             } else {
                 const notBeforeStr = notBeforeDate.toUTCString();
                 const notAfterStr = notAfterDate.toUTCString();

                 if (now < notBeforeDate) {
                    validityStatus = `Not Yet Valid (Starts: ${notBeforeStr})`;
                    validityClass = 'status-not-yet-valid';
                 } else if (now >= notAfterDate) {
                    validityStatus = `Expired (Expired: ${notAfterStr})`;
                     validityClass = 'status-expired';
                 } else {
                    validityStatus = `Valid (Expires: ${notAfterStr})`;
                     validityClass = 'status-valid';
                 }
                 // Add valid from date only if dates were parsable
                  analysisHtml = `<div><span class="label">Valid From:</span> ${notBeforeStr}</div>`;
                  analysisHtml += `<div><span class="label">Valid To:</span> ${notAfterStr}</div>`;
            }

            let analysisHtml = `
                <div><span class="label">Subject:</span> ${subject}</div>
                <div><span class="label">Issuer:</span> ${issuer}</div>
            `;

            // Add dates only if they were parsed correctly
            if (!isNaN(notBeforeDate.getTime())) {
                analysisHtml += `<div><span class="label">Valid From:</span> ${notBeforeDate.toUTCString()}</div>`;
            }
            if (!isNaN(notAfterDate.getTime())) {
                 analysisHtml += `<div><span class="label">Valid To:</span> ${notAfterDate.toUTCString()}</div>`;
            }
            // Add calculated status
            analysisHtml += `<div><span class="label">Status:</span> <span class="${validityClass}">${validityStatus}</span></div>`;

            analysisHtml += `<div><span class="label">Serial Number:</span> ${cert.getSerialNumberHex()}</div>`;
            analysisHtml += `<div><span class="label">Signature Algorithm:</span> ${cert.getSignatureAlgorithmName()}</div>`;
            analysisHtml += `<div><span class="label">Version:</span> ${cert.getVersion()}</div>`;


             // Public Key Info
             try {
                 const pubKey = cert.getPublicKey(); // This gives a key object
                 if (pubKey) {
                     let keyType = 'Unknown';
                     let keySize = 'N/A';
                     let keyDetails = '';

                     if (pubKey.type === 'RSA') { // jsrsasign uses 'type' property
                         keyType = 'RSA';
                         keySize = pubKey.getBitLength() + ' bits'; // Use getBitLength for RSA
                     } else if (pubKey.type === 'EC') {
                          keyType = 'ECDSA';
                          keySize = pubKey.getCurveName ? `Curve: ${pubKey.getCurveName()}` : 'N/A'; // Check curve name
                     } // Add more types like DSA if needed

                      analysisHtml += `<div><span class="label">Public Key Type:</span> ${keyType}</div>`;
                      analysisHtml += `<div><span class="label">Public Key Size:</span> ${keySize}</div>`;

                     // Optionally display the public key PEM
                     // const pubKeyPEM = jsrsasign.KEYUTIL.getPEM(pubKey);
                     // analysisHtml += `<div><span class="label">Public Key PEM:</span><pre>${pubKeyPEM}</pre></div>`;

                 } else {
                     analysisHtml += `<div><span class="label">Public Key Info:</span> <span class="status-warning">Could not retrieve public key object</span></div>`;
                 }
             } catch (pkError) {
                  console.warn("Could not extract public key details:", pkError);
                 analysisHtml += `<div><span class="label">Public Key Info:</span> <span class="status-warning">Error reading details (${pkError.message})</span></div>`;
             }

            certAnalysisOutput.innerHTML = analysisHtml;

        } catch (e) {
            console.error("Error parsing certificate:", e);
            displayError(certAnalysisOutput, `Failed to parse PEM certificate. It might be corrupted or not a valid X.509 certificate. Error: ${e.message}`);
        }
    });


    // --- Base64 Encoder/Decoder Logic ---
    base64EncodeBtn.addEventListener('click', () => {
        try {
            // Handle potential UTF-8 issues in btoa
            const utf8Bytes = new TextEncoder().encode(base64Input.value);
            const base64String = btoa(String.fromCharCode(...utf8Bytes));
            base64Output.value = base64String;
        } catch (e) {
            base64Output.value = `Error encoding: ${e.message}`;
        }
    });

    base64DecodeBtn.addEventListener('click', () => {
        try {
            // Handle potential UTF-8 issues in atob
            const binaryString = atob(base64Input.value);
            const bytes = Uint8Array.from(binaryString, c => c.charCodeAt(0));
            base64Output.value = new TextDecoder().decode(bytes);
        } catch (e) {
            base64Output.value = `Error decoding: ${e.message}. Input might not be valid Base64 or decoded text is not valid UTF-8.`;
        }
    });

     // --- URL Encoder/Decoder Logic ---
     urlEncodeBtn.addEventListener('click', () => {
        try {
            urlOutput.value = encodeURIComponent(urlInput.value);
        } catch (e) {
            urlOutput.value = `Error encoding: ${e.message}`;
        }
    });

    urlDecodeBtn.addEventListener('click', () => {
        try {
            // Use decodeURIComponent for full decoding
            urlOutput.value = decodeURIComponent(urlInput.value.replace(/\+/g, ' ')); // Also handle + for space
        } catch (e) {
            urlOutput.value = `Error decoding: ${e.message}. Input might not be valid URL encoding.`;
        }
    });

}); // End DOMContentLoaded