document.getElementById('analyzeButton').addEventListener('click', () => {
  const resultElement = document.getElementById('result');
  const progressBar = document.getElementById('progressBar');
  const progressContainer = document.getElementById('progressContainer');
  const analyzeButton = document.getElementById('analyzeButton');
  const generateReportButton = document.getElementById('generateReportButton');
  const recopyDescriptionButton = document.getElementById('recopyDescriptionButton');
  resultElement.textContent = 'Analyzing...';
  progressBar.style.width = '0%';
  progressBar.style.display = 'block';
  generateReportButton.style.display = 'none';
  recopyDescriptionButton.style.display = 'none';

  navigator.clipboard.readText().then(text => {
    if (text) {
      chrome.runtime.sendMessage({ action: 'analyze', data: text });

      chrome.runtime.onMessage.addListener((message) => {
        if (message.action === 'progress') {
          const progressPercentage = `${message.progress}%`;
          progressBar.style.width = progressPercentage;
          progressBar.style.maxWidth = analyzeButton.offsetWidth + 'px';
        } else if (message.action === 'complete') {
          progressBar.style.width = '100%';
          resultElement.innerHTML = '<b>Description copied to clipboard</b>';
          generateReportButton.style.display = 'block';
          recopyDescriptionButton.style.display = 'block';
          navigator.clipboard.writeText(message.description).then(() => {
            console.log('Description copied to clipboard');
          }).catch(err => {
            console.error('Failed to copy description to clipboard:', err);
          });
        } else if (message.action === 'detailedReport') {
          resultElement.innerHTML = '<b>Detailed report copied to clipboard</b>';
          navigator.clipboard.writeText(message.result).then(() => {
            console.log('Detailed report copied to clipboard');
          }).catch(err => {
            console.error('Failed to copy detailed report to clipboard:', err);
          });
        } else if (message.action === 'recopyDescription') {
          resultElement.innerHTML = '<b>Description copied to clipboard</b>';
          navigator.clipboard.writeText(message.description).then(() => {
            console.log('Description copied to clipboard');
          }).catch(err => {
            console.error('Failed to copy description to clipboard:', err);
          });
        } else if (message.action === 'error') {
          resultElement.textContent = `Analysis failed: ${message.error}`;
          progressBar.style.width = '0%';
        }
      });
    } else {
      resultElement.textContent = 'Clipboard is empty.';
    }
  }).catch(err => {
    resultElement.textContent = `Failed to read clipboard: ${err}`;
  });
});

document.getElementById('recopyDescriptionButton').addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'recopyDescription' });
});

document.getElementById('generateReportButton').addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'generateReport' });
});

// Retrieve and set progress on popup open
document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.local.get(['progress', 'analyzing'], (items) => {
    if (items.analyzing) {
      const progressBar = document.getElementById('progressBar');
      const progressContainer = document.getElementById('progressContainer');
      const analyzeButton = document.getElementById('analyzeButton');
      progressBar.style.width = `${items.progress}%`;
      progressBar.style.maxWidth = analyzeButton.offsetWidth + 'px';
      progressBar.style.display = 'block';
    }
  });
});
