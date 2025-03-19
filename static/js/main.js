document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const spinner = document.getElementById('spinner');
    const resultContainer = document.getElementById('result-container');
    const resultAlert = document.getElementById('result-alert');
    const resultHeading = document.getElementById('result-heading');
    const resultMessage = document.getElementById('result-message');
    const riskMeter = document.getElementById('risk-meter');
    const riskLevel = document.getElementById('risk-level');
    const riskDetails = document.getElementById('risk-details');
    const safeBrowsingMessage = document.getElementById('safe-browsing-message');
    const threatList = document.getElementById('threat-list');
    const featuresTable = document.getElementById('features-table');
    
    // Form submission handler
    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Validate URL
        if (!urlInput.value) {
            urlInput.classList.add('is-invalid');
            return;
        }
        
        // Reset validation state
        urlInput.classList.remove('is-invalid');
        
        // Show spinner
        spinner.classList.remove('d-none');
        analyzeBtn.setAttribute('disabled', 'disabled');
        
        // Send request to server
        fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `url=${encodeURIComponent(urlInput.value)}`
        })
        .then(response => response.json())
        .then(data => {
            displayResult(data);
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while analyzing the URL. Please try again.');
        })
        .finally(() => {
            // Hide spinner
            spinner.classList.add('d-none');
            analyzeBtn.removeAttribute('disabled');
        });
    });
    
    // Display result
    function displayResult(data) {
        // Show result container
        resultContainer.classList.remove('d-none');
        
        // Update risk meter
        riskMeter.style.width = `${data.probability}%`;
        riskLevel.textContent = data.risk_level;
        
        // Set risk meter color
        if (data.probability < 20) {
            riskMeter.className = 'progress-bar bg-success';
        } else if (data.probability < 60) {
            riskMeter.className = 'progress-bar bg-warning';
        } else {
            riskMeter.className = 'progress-bar bg-danger';
        }
        
        // Update result alert
        if (data.is_phishing) {
            resultAlert.className = 'alert phishing';
            resultHeading.textContent = 'Potential Phishing URL Detected';
            resultMessage.textContent = `This URL has been identified as a potential phishing site with ${data.probability.toFixed(1)}% confidence.`;
        } else {
            resultAlert.className = 'alert safe';
            resultHeading.textContent = 'URL Appears Safe';
            resultMessage.textContent = `This URL appears to be safe with ${(100 - data.probability).toFixed(1)}% confidence.`;
        }
        
        // Update risk details
        if (data.probability < 20) {
            riskDetails.textContent = 'This URL shows few or no indicators of being a phishing site.';
        } else if (data.probability < 60) {
            riskDetails.textContent = 'This URL shows some indicators of being a phishing site. Proceed with caution.';
        } else {
            riskDetails.textContent = 'This URL shows strong indicators of being a phishing site. We recommend not visiting this site.';
        }
        
        // Update Safe Browsing result
        if (data.safe_browsing.is_safe) {
            safeBrowsingMessage.textContent = 'This URL is not on Google Safe Browsing\'s list of dangerous sites.';
            threatList.innerHTML = '';
        } else {
            safeBrowsingMessage.textContent = 'This URL is on Google Safe Browsing\'s list of dangerous sites:';
            threatList.innerHTML = '';
            
            data.safe_browsing.threats.forEach(threat => {
                const li = document.createElement('li');
                li.className = 'list-group-item list-group-item-danger';
                li.textContent = `${threat.threat_type} (${threat.platform_type})`;
                threatList.appendChild(li);
            });
        }
        
        // Update features table
        featuresTable.innerHTML = '';
        Object.entries(data.features).forEach(([feature, value]) => {
            const row = document.createElement('tr');
            
            const featureCell = document.createElement('td');
            featureCell.textContent = feature;
            row.appendChild(featureCell);
            
            const valueCell = document.createElement('td');
            valueCell.textContent = value;
            row.appendChild(valueCell);
            
            featuresTable.appendChild(row);
        });
    }
});