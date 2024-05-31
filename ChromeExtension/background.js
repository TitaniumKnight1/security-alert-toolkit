chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'analyze') {
    let jsonData;
    try {
      jsonData = JSON.parse(message.data);
      chrome.storage.local.set({ analyzing: true, progress: 0 });
      processPhishingReport(jsonData.fields, (progress) => {
        chrome.storage.local.set({ progress: progress });
        chrome.runtime.sendMessage({ action: 'progress', progress });
      }).then(report => {
        const description = formatDescription(report);
        const result = formatReport(report);
        chrome.storage.local.set({ description: description, result: result, analyzing: false }, () => {
          chrome.runtime.sendMessage({ action: 'complete', description: description });
        });
        sendResponse({ success: true });
      }).catch(error => {
        chrome.runtime.sendMessage({ action: 'error', error: error.message });
        sendResponse({ error: error.message });
      });
    } catch (error) {
      chrome.runtime.sendMessage({ action: 'error', error: `Invalid JSON input: ${error.message}` });
      sendResponse({ error: `Invalid JSON input: ${error.message}` });
    }
    return true; // Indicates that the response is sent asynchronously
  } else if (message.action === 'generateReport') {
    chrome.storage.local.get(['result'], (items) => {
      if (items.result) {
        chrome.runtime.sendMessage({ action: 'detailedReport', result: items.result });
      }
    });
    sendResponse({ success: true });
  } else if (message.action === 'recopyDescription') {
    chrome.storage.local.get(['description'], (items) => {
      if (items.description) {
        chrome.runtime.sendMessage({ action: 'recopyDescription', description: items.description });
      }
    });
    sendResponse({ success: true });
  }
  return true; // Indicates that the response is sent asynchronously
});

function urlToBase64(url) {
  return btoa(url).replace(/=+$/, '');
}

async function queryVirusTotal(urlOrHash, isFile, progressCallback, progress, increment) {
  try {
    const encodedId = isFile ? urlOrHash : urlToBase64(urlOrHash);
    const endpoint = isFile ? `https://www.virustotal.com/api/v3/files/${encodedId}` : `https://www.virustotal.com/api/v3/urls/${encodedId}`;
    const response = await fetch(endpoint, {
      headers: { 'x-apikey': '86bae1528f5c1e9af939b858009d30c528fb32c95be9d0e878ae385edab70b3e' }
    });
    if (!response.ok) {
      if (response.status === 404) {
        return { notFound: true };
      }
      const errorText = await response.text();
      throw new Error(`VirusTotal request failed: ${response.statusText} - ${errorText}`);
    }
    const data = await response.json();
    if (data.error && data.error.code === 'NotFoundError') {
      return { notFound: true };
    }
    progress += increment;
    progressCallback(progress);
    return data;
  } catch (error) {
    throw new Error(`Failed to query VirusTotal: ${error.message}`);
  }
}

async function checkIpAbuseIPDB(ip, progressCallback, progress, increment) {
  try {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose=`, {
      headers: {
        'Accept': 'application/json',
        'Key': '428109f78f9ca804515358052cde0fa05bd4bc2d06098d268d2688662acd140824f143ba01dc36e6'
      }
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`AbuseIPDB request failed: ${response.statusText} - ${errorText}`);
    }
    progress += increment;
    progressCallback(progress);
    return response.json();
  } catch (error) {
    throw new Error(`Failed to query AbuseIPDB: ${error.message}`);
  }
}

function extractEmail(emailStr) {
  const match = emailStr.match(/<(.+?)>/);
  return match ? match[1] : emailStr.match(/[^@]+@[^@]+\.[^@]+/) ? emailStr : '';
}

function extractIpFromAuthResults(authResults) {
  const match = authResults.match(/sender IP is (\d+\.\d+\.\d+\.\d+)/);
  return match ? match[1] : '';
}

async function processPhishingReport(fields, progressCallback) {
  let progress = 0;
  const to = extractEmail(fields['email.reporter'] ? fields['email.reporter'][0] : '');
  const fromAddress = extractEmail(fields['email.from.address'] ? fields['email.from.address'][0] : '');
  const replyTo = extractEmail(fields['email.headers.Reply-To'] ? fields['email.headers.Reply-To'][0] : '');
  const subject = fields['email.subject.text'] ? fields['email.subject.text'][0] : '';
  const body = (fields['email.body_plaintext'] ? fields['email.body_plaintext'][0] : '').replace(/\n/g, ' ').replace(/\r/g, '').trim();
  const urls = [...new Set(fields['email.urls.data'] || [])];
  const attachments = fields['email.attachments'] || [];
  const authResults = fields['email.headers.Authentication-Results'] ? fields['email.headers.Authentication-Results'][0] : '';

  const totalSteps = urls.length + attachments.reduce((acc, attachment) => acc + (attachment['file.hash.sha256'] || []).length, 0) + 2; // +2 for initial checks and AbuseIPDB
  const increment = 100 / totalSteps;

  const senderIp = extractIpFromAuthResults(authResults);
  const abuseIpDbResult = await checkIpAbuseIPDB(senderIp, progressCallback, progress, increment);
  progress += increment;
  progressCallback(progress);

  const virustotalUrlResults = {};
  for (const url of urls) {
    try {
      const result = await queryVirusTotal(url, false, progressCallback, progress, increment);
      virustotalUrlResults[url] = result.notFound ? { notFound: true } : result;
    } catch (error) {
      virustotalUrlResults[url] = { error: error.message };
    }
    // Wait for 15 seconds between each VirusTotal request to respect the rate limit
    await new Promise(resolve => setTimeout(resolve, 15000));
    progress += increment;
    progressCallback(progress);
  }

  const virustotalFileResults = {};
  for (const attachment of attachments) {
    for (const fileHash of attachment['file.hash.sha256'] || []) {
      try {
        const result = await queryVirusTotal(fileHash, true, progressCallback, progress, increment);
        virustotalFileResults[fileHash] = result.notFound ? { notFound: true } : result;
      } catch (error) {
        virustotalFileResults[fileHash] = { error: error.message };
      }
      // Wait for 15 seconds between each VirusTotal request to respect the rate limit
      await new Promise(resolve => setTimeout(resolve, 15000));
      progress += increment;
      progressCallback(progress);
    }
  }

  return {
    to,
    from: fromAddress,
    reply_to: replyTo,
    subject,
    body,
    sender_ip: senderIp,
    abuseipdb_result: abuseIpDbResult,
    urls: virustotalUrlResults,
    files: virustotalFileResults,
    attachments
  };
}

function formatDescription(results) {
  const to = results.to ? `\`${results.to}\`` : '`an unknown reporter`';
  const from = results.from ? `\`${results.from}\`` : '`an unknown sender`';
  const subject = results.subject ? `\`${results.subject}\`` : '`an unknown subject`';

  if (!results.subject) {
    return `${to} reported an email originating from ${from} with no subject.`;
  }

  return `${to} reported an email originating from ${from} with the subject ${subject}.`;
}

function formatReport(results) {
  let output = [];
  output.push(`To: \`${results.to || 'N/A'}\``);
  output.push(`From: \`${results.from || 'N/A'}\``);
  if (results.reply_to) {
    output.push(`Reply: \`${results.reply_to}\``);
  }
  output.push(`Subject: \`${results.subject || 'N/A'}\``);

  output.push(`Sender IP: \`${results.sender_ip || 'N/A'}\``);
  output.push('AbuseIPDB Result:');
  output.push(`  - IP Address: ${results.abuseipdb_result.data.ipAddress}`);
  output.push(`  - Abuse Confidence Score: ${results.abuseipdb_result.data.abuseConfidenceScore}`);
  output.push(`  - Country: ${results.abuseipdb_result.data.countryName}`);
  output.push(`  - Usage Type: ${results.abuseipdb_result.data.usageType}`);
  output.push(`  - ISP: ${results.abuseipdb_result.data.isp}`);
  output.push(`  - Domain: ${results.abuseipdb_result.data.domain}`);
  output.push(`  - Total Reports: ${results.abuseipdb_result.data.totalReports}`);
  output.push(`  - Last Reported At: ${results.abuseipdb_result.data.lastReportedAt}`);

  output.push('Body:');
  output.push(results.body ? `\`\`\`\n${results.body}\n\`\`\`` : 'N/A');

  output.push('Urls:');
  if (Object.keys(results.urls).length === 0) {
    output.push('N/A');
  } else {
    for (const [url, result] of Object.entries(results.urls)) {
      const domain = new URL(url).hostname;
      const formattedDomain = domain.replace(/.*?:\/\//g, '').replace(/\/.*/, ''); // Removes protocol and path
      if (result.notFound) {
        output.push(`\`${formattedDomain}\`: N/A`);
      } else if (result.data && result.data.id) {
        output.push(`\`${formattedDomain}\`: [VirusTotal](https://www.virustotal.com/gui/url/${result.data.id}/detection)`);
      } else {
        output.push(`\`${formattedDomain}\`: ${result.error ? result.error : 'No VT Results'}`);
      }
    }
  }

  output.push('Files:');
  if (Object.keys(results.files).length === 0) {
    output.push('N/A');
  } else {
    for (const [fileHash, result] of Object.entries(results.files)) {
      const attachment = results.attachments.find(att => att['file.hash.sha256'] && att['file.hash.sha256'][0] === fileHash);
      if (attachment) {
        const fileName = attachment['file.name'] ? attachment['file.name'][0] : 'unknown';
        const fileMd5 = attachment['file.hash.md5'] ? attachment['file.hash.md5'][0] : 'unknown';
        output.push(`Name: ${fileName}`);
        output.push(`MD5 Hash: ${fileMd5}`);
        output.push(`SHA256 Hash: ${fileHash}`);
      }
      if (result.notFound) {
        output.push('No VirusTotal result');
      } else {
        const virustotalLink = `https://www.virustotal.com/gui/file/${fileHash}/detection`;
        output.push(`[VirusTotal](${virustotalLink})`);
      }
    }
  }

  return output.join('\n');
}