// Main JavaScript for DID Verification Platform

function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    if (tooltipTriggerList.length > 0) {
        const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    }
    
    // Face image upload preview
    const faceImageInput = document.getElementById('face-image-input');
    const facePreview = document.getElementById('face-preview');
    
    if (faceImageInput && facePreview) {
        faceImageInput.addEventListener('change', function(event) {
            const file = event.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    facePreview.innerHTML = `<img src="${e.target.result}" alt="Face Preview">`;
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    // Credential verification form
    const verifyForm = document.getElementById('verify-credential-form');
    const verifyResult = document.getElementById('verify-result');
    
    if (verifyForm && verifyResult) {
        verifyForm.addEventListener('submit', async function(event) {
            event.preventDefault();
            
            const credentialId = document.getElementById('credential-id').value;
            
            try {
                showLoading();
                
                const response = await fetch('/api/verify_credential/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken(),
                    },
                    body: JSON.stringify({
                        credential_id: credentialId
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    if (data.verified) {
                        verifyResult.innerHTML = `
                            <div class="alert alert-success mt-3">
                                <h5>✅ Verification Successful</h5>
                                <p>Credential type: ${data.credential_type}</p>
                                <p>Issuer: ${data.issuer}</p>
                                <p>Subject: ${data.subject}</p>
                                <p>Issuance date: ${new Date(data.issuance_date).toLocaleString()}</p>
                                <div class="blockchain-info mt-2">
                                    <p class="mb-1"><strong>Blockchain verification:</strong> ${data.blockchain_confirmed ? '✅ Confirmed' : '❌ Not found'}</p>
                                    ${data.blockchain_info ? `
                                        <small>Transaction: ${data.blockchain_info.tx_hash}</small><br>
                                        <small>Block: ${data.blockchain_info.block_number}</small>
                                    ` : ''}
                                </div>
                            </div>
                        `;
                    } else {
                        verifyResult.innerHTML = `
                            <div class="alert alert-danger mt-3">
                                <h5>❌ Verification Failed</h5>
                                <p>${data.error || 'Invalid credential'}</p>
                            </div>
                        `;
                    }
                } else {
                    verifyResult.innerHTML = `
                        <div class="alert alert-danger mt-3">
                            <h5>❌ Verification Failed</h5>
                            <p>${data.error || 'Invalid credential'}</p>
                        </div>
                    `;
                }
            } catch (error) {
                verifyResult.innerHTML = `
                    <div class="alert alert-danger mt-3">
                        <h5>❌ Error</h5>
                        <p>An error occurred during verification: ${error.message}</p>
                    </div>
                `;
            } finally {
                hideLoading();
            }
        });
    }
    
    // Helper functions
    function getCsrfToken() {
        return document.querySelector('[name=csrfmiddlewaretoken]').value;
    }
    
    function showLoading() {
        const spinner = document.createElement('div');
        spinner.className = 'spinner-overlay';
        spinner.innerHTML = `
            <div class="spinner-border text-light" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        `;
        document.body.appendChild(spinner);
    }
    
    function hideLoading() {
        const spinner = document.querySelector('.spinner-overlay');
        if (spinner) {
            spinner.remove();
        }
    }
});
