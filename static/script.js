// Function to handle switching between Email, SMS, Link, and QR tabs
function switchTab(tabId) {
    // Hide all sections
    document.querySelectorAll('.tab-content').forEach(section => {
        section.classList.remove('active');
    });
    
    // Remove active class from all buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show the selected section
    const targetSection = document.getElementById(`${tabId}-section`);
    if (targetSection) targetSection.classList.add('active');
    
    // Find the clicked button and make it active
    const buttons = document.querySelectorAll('.tab-btn');
    if (tabId === 'email' && buttons[0]) buttons[0].classList.add('active');
    if (tabId === 'sms' && buttons[1]) buttons[1].classList.add('active');
    if (tabId === 'link' && buttons[2]) buttons[2].classList.add('active');
    if (tabId === 'qr' && buttons[3]) buttons[3].classList.add('active');

    // Clear old results and highlights when switching tabs
    document.getElementById('result-box').classList.add('hidden');
    clearHighlights();
}

// Function to send text/link data to the Flask backend
async function analyzeThreat(type) {
    let inputData = '';
    const inputId = `${type}-input`;
    
    // Get the correct input based on the active tab
    if (type === 'email') {
        inputData = document.getElementById('email-input').value;
    } else if (type === 'sms') {
        inputData = document.getElementById('sms-input').value;
    } else if (type === 'link') {
        inputData = document.getElementById('link-input').value;
    }

    if (!inputData.trim()) {
        alert("Please enter some text or a link to analyze.");
        return;
    }

    // Change button text to show loading state
    const currentBtn = event.target;
    const originalText = currentBtn.innerText;
    currentBtn.innerText = "Analyzing...";
    currentBtn.disabled = true;

    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ text: inputData, type: type })
        });

        const result = await response.json();

        if (result.error) {
            alert(result.error);
            return;
        }
        
        displayResult(result.prediction, result.confidence, result.trigger_words, inputId);

    } catch (error) {
        console.error("Error connecting to backend:", error);
        alert("Failed to connect to the server. Is your Flask app running?");
    } finally {
        currentBtn.innerText = originalText;
        currentBtn.disabled = false;
    }
}

// Function to handle QR Image upload and scan
async function analyzeQRThreat() {
    const fileInput = document.getElementById('qr-file-input');
    if (!fileInput || fileInput.files.length === 0) {
        alert("Please select a QR code image file to upload.");
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    const currentBtn = event.target;
    const originalText = currentBtn.innerText;
    currentBtn.innerText = "Decoding QR...";
    currentBtn.disabled = true;

    try {
        const response = await fetch('/predict-qr', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (result.error) {
            alert(result.error);
            return;
        }

        displayQRResult(result.prediction, result.confidence, result.extracted_text);

    } catch (error) {
        console.error("Error connecting to backend:", error);
        alert("Failed to connect to the server.");
    } finally {
        currentBtn.innerText = originalText;
        currentBtn.disabled = false;
    }
}

// Function to update the UI with text/link predictions
function displayResult(prediction, confidence, triggerWords = [], inputId) {
    const resultBox = document.getElementById('result-box');
    const badge = document.getElementById('result-badge');
    const scoreSpan = document.getElementById('confidence-score');

    badge.classList.remove('safe', 'spam', 'phishing');
    clearHighlights();

    const cleanPred = prediction.toLowerCase();

    if (cleanPred === 'ham' || cleanPred === 'safe') {
        badge.classList.add('safe');
        badge.innerText = "SAFE";
    } else if (cleanPred === 'spam') {
        badge.classList.add('spam');
        badge.innerText = "SPAM";
    } else if (cleanPred === 'phishing') {
        badge.classList.add('phishing');
        badge.innerText = "PHISHING";
    } else {
        badge.innerText = prediction.toUpperCase();
    }

    if ((cleanPred === 'spam' || cleanPred === 'phishing') && triggerWords && triggerWords.length > 0) {
        highlightTriggerWords(inputId, triggerWords);
    }

    scoreSpan.innerText = confidence;
    resultBox.classList.remove('hidden');
}

// Function to update the UI with QR scan results
function displayQRResult(prediction, confidence, extractedText) {
    const resultBox = document.getElementById('result-box');
    const badge = document.getElementById('result-badge');
    const scoreSpan = document.getElementById('confidence-score');

    badge.classList.remove('safe', 'spam', 'phishing');
    clearHighlights();

    const cleanPred = prediction.toLowerCase();

    if (cleanPred === 'ham' || cleanPred === 'safe') {
        badge.classList.add('safe');
        badge.innerText = "SAFE QR CODE";
    } else if (cleanPred === 'spam') {
        badge.classList.add('spam');
        badge.innerText = "SPAM QR CODE";
    } else {
        badge.classList.add('phishing');
        badge.innerText = "MALICIOUS QR (PHISHING)";
    }

    scoreSpan.innerText = confidence;
    
    // Display decoded payload inside highlight box structure
    let infoDiv = document.getElementById('qr-extracted-info');
    if (!infoDiv) {
        infoDiv = document.createElement('div');
        infoDiv.id = 'qr-extracted-info';
        infoDiv.className = 'highlight-box';
        resultBox.appendChild(infoDiv);
    }
    infoDiv.innerHTML = `<p class="highlight-title">🔍 Decoded QR Code Payload:</p><div class="highlight-content"><code>${extractedText}</code></div>`;
    infoDiv.style.display = 'block';

    resultBox.classList.remove('hidden');
}

// Function to visually highlight suspicious words identified by LIME
function highlightTriggerWords(inputId, words) {
    const inputElement = document.getElementById(inputId);
    if (!inputElement) return;

    let content = inputElement.value;
    
    let displayDiv = document.getElementById(`${inputId}-highlight`);
    if (!displayDiv) {
        displayDiv = document.createElement('div');
        displayDiv.id = `${inputId}-highlight`;
        displayDiv.className = 'highlight-box';
        inputElement.parentNode.insertBefore(displayDiv, inputElement.nextSibling);
    }

    words.forEach(word => {
        const escapedWord = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`\\b(${escapedWord})\\b`, 'gi');
        content = content.replace(regex, '<mark class="highlight-tag">$1</mark>');
    });

    displayDiv.innerHTML = `<p class="highlight-title">⚠️ AI Identified Suspicious Words:</p><div class="highlight-content">${content}</div>`;
    displayDiv.style.display = 'block';
}

// Function to hide all active highlight boxes
function clearHighlights() {
    document.querySelectorAll('.highlight-box').forEach(el => {
        el.style.display = 'none';
        el.innerHTML = '';
    });
}
// --- Upgraded Backend-Powered AI Security Agent ---
async function sendChatMessage() {
    const inputField = document.getElementById('chat-input');
    const chatBody = document.getElementById('chat-messages');
    const userText = inputField.value.trim();

    if (!userText) return;

    // Append User Message to Chat UI
    const userMsgDiv = document.createElement('div');
    userMsgDiv.className = 'chat-msg user';
    userMsgDiv.innerText = userText;
    chatBody.appendChild(userMsgDiv);

    inputField.value = '';
    chatBody.scrollTop = chatBody.scrollHeight;

    // Show temporary typing indicator
    const typingDiv = document.createElement('div');
    typingDiv.className = 'chat-msg bot typing';
    typingDiv.id = 'typing-indicator';
    typingDiv.innerText = 'AI Agent is thinking...';
    chatBody.appendChild(typingDiv);
    chatBody.scrollTop = chatBody.scrollHeight;

    try {
        // Send request to Flask backend agent endpoint
        const response = await fetch('/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ message: userText })
        });

        const result = await response.json();
        
        // Remove typing indicator
        document.getElementById('typing-indicator').remove();

        const botMsgDiv = document.createElement('div');
        botMsgDiv.className = 'chat-msg bot';
        botMsgDiv.innerText = result.response || "SecureGuard Agent is online and ready.";
        chatBody.appendChild(botMsgDiv);

    } catch (error) {
        console.error("Chat error:", error);
        document.getElementById('typing-indicator').remove();
        
        const errorDiv = document.createElement('div');
        errorDiv.className = 'chat-msg bot';
        errorDiv.innerText = "Error connecting to AI security agent backend.";
        chatBody.appendChild(errorDiv);
    } finally {
        chatBody.scrollTop = chatBody.scrollHeight;
    }
}
// Allow pressing 'Enter' to send chat message
document.addEventListener("DOMContentLoaded", () => {
    const chatInput = document.getElementById('chat-input');
    if (chatInput) {
        chatInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                sendChatMessage();
            }
        });
    }
});