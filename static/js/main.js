/**
 * Main JavaScript file for the Enterprise SMTP Server
 * Handles interactive functionality for the dashboard and other pages
 */

// Global variables for authentication
let authToken = localStorage.getItem('authToken');

/**
 * Get API token from the server
 * @param {string} email - User email
 * @param {string} password - User password
 * @returns {Promise} - Promise that resolves with authentication token
 */
async function getApiToken(email, password) {
    try {
        const response = await fetch('/api/auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        if (!response.ok) {
            throw new Error('Authentication failed');
        }

        const data = await response.json();
        authToken = data.token;
        localStorage.setItem('authToken', authToken);
        return authToken;
    } catch (error) {
        console.error('Authentication error:', error);
        throw error;
    }
}

/**
 * Send an email using the API
 * @param {Object} emailData - Email data object
 * @returns {Promise} - Promise that resolves with API response
 */
async function sendEmail(emailData) {
    try {
        // Make sure we have an auth token
        if (!authToken) {
            throw new Error('Authentication required');
        }

        const response = await fetch('/api/send_email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(emailData)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to send email');
        }

        return await response.json();
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

/**
 * Fetch recent emails from the API
 * @returns {Promise} - Promise that resolves with recent emails data
 */
async function getRecentEmails() {
    try {
        // Mock function - in a real implementation, this would fetch from the API
        // This should be replaced with actual API call in production
        
        // For now, we'll simulate a successful API response with empty data
        return {
            emails: []
        };
    } catch (error) {
        console.error('Error fetching recent emails:', error);
        throw error;
    }
}

/**
 * Get email statistics from the API
 * @returns {Promise} - Promise that resolves with email statistics
 */
async function getEmailStats() {
    try {
        // Make sure we have an auth token
        if (!authToken) {
            throw new Error('Authentication required');
        }

        const response = await fetch('/api/email_stats', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (!response.ok) {
            throw new Error('Failed to fetch email statistics');
        }

        return await response.json();
    } catch (error) {
        console.error('Error fetching email statistics:', error);
        throw error;
    }
}

/**
 * Display an error message in the specified element
 * @param {string} elementId - ID of the element to display error in
 * @param {string} message - Error message to display
 */
function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.classList.remove('d-none');
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            element.classList.add('d-none');
        }, 5000);
    }
}

/**
 * Display a success message in the specified element
 * @param {string} elementId - ID of the element to display success message in
 * @param {string} message - Success message to display
 */
function showSuccess(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.classList.remove('d-none');
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            element.classList.add('d-none');
        }, 5000);
    }
}

/**
 * Load recent emails and populate the table
 */
function loadRecentEmails() {
    const tableBody = document.getElementById('recentEmailsTable');
    if (!tableBody) return;

    // Clear the table
    tableBody.innerHTML = '<tr><td colspan="6" class="text-center"><div class="spinner-border spinner-border-sm" role="status"></div> Loading...</td></tr>';

    // Get recent emails from the server
    getRecentEmails()
        .then(data => {
            if (!data.emails || data.emails.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No emails found</td></tr>';
                return;
            }

            // Populate the table
            tableBody.innerHTML = '';
            data.emails.forEach(email => {
                const row = document.createElement('tr');
                
                // Define status badge class based on status
                let statusClass = 'bg-secondary';
                if (email.status === 'sent') statusClass = 'bg-success';
                if (email.status === 'failed') statusClass = 'bg-danger';
                if (email.status === 'queued') statusClass = 'bg-warning';
                
                row.innerHTML = `
                    <td>${email.id}</td>
                    <td>${truncateText(email.recipients, 30)}</td>
                    <td>${truncateText(email.subject, 40)}</td>
                    <td><span class="badge ${statusClass}">${email.status}</span></td>
                    <td>${formatDate(email.sent_at)}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-info view-details" data-id="${email.id}">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" data-id="${email.id}">
                            <i class="fas fa-redo-alt"></i>
                        </button>
                    </td>
                `;
                tableBody.appendChild(row);
            });
            
            // Add event listeners to view details buttons
            document.querySelectorAll('.view-details').forEach(button => {
                button.addEventListener('click', () => {
                    const emailId = button.getAttribute('data-id');
                    viewEmailDetails(emailId);
                });
            });
        })
        .catch(error => {
            tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Error loading emails: ${error.message}</td></tr>`;
        });
}

/**
 * Initialize event listeners for the dashboard page
 */
function initDashboard() {
    // Send email form submission
    const sendEmailBtn = document.getElementById('sendEmailBtn');
    if (sendEmailBtn) {
        sendEmailBtn.addEventListener('click', function() {
            const sender = document.getElementById('sender').value;
            const recipientsStr = document.getElementById('recipients').value;
            const subject = document.getElementById('subject').value;
            const body = document.getElementById('body').value;
            const htmlBody = document.getElementById('htmlBody').value;

            // Basic validation
            if (!sender || !recipientsStr || !subject || !body) {
                showError('emailError', 'Please fill in all required fields');
                return;
            }

            // Parse recipients
            const recipients = recipientsStr.split(',').map(email => email.trim());

            // Prepare email data
            const emailData = {
                sender,
                recipients,
                subject,
                body,
                html_body: htmlBody || undefined
            };

            // Disable button and show loading
            sendEmailBtn.disabled = true;
            sendEmailBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sending...';

            // Send the email
            sendEmail(emailData)
                .then(result => {
                    // Show success message
                    showSuccess('emailSuccess', `Email queued successfully with ID: ${result.message_id}`);
                    
                    // Reset form
                    document.getElementById('sendEmailForm').reset();

                    // Update stats (in a real app, we would refresh the stats from the server)
                    setTimeout(() => {
                        loadRecentEmails();
                        // Here we would update stats by fetching new data from server
                    }, 2000);
                })
                .catch(error => {
                    // Show error message
                    showError('emailError', `Failed to send email: ${error.message}`);
                })
                .finally(() => {
                    // Re-enable button
                    sendEmailBtn.disabled = false;
                    sendEmailBtn.innerHTML = '<i class="fas fa-paper-plane me-1"></i> Send Email';
                });
        });
    }

    // Chart period selection (Week/Month)
    const periodButtons = document.querySelectorAll('[data-period]');
    if (periodButtons.length) {
        periodButtons.forEach(button => {
            button.addEventListener('click', function() {
                // Remove active class from all buttons
                periodButtons.forEach(btn => btn.classList.remove('active'));
                
                // Add active class to clicked button
                this.classList.add('active');
                
                // Update chart based on selected period
                const period = this.getAttribute('data-period');
                updateChartPeriod(period);
            });
        });
    }
}

/**
 * View email details in a modal
 * @param {string} emailId - ID of the email to view
 */
function viewEmailDetails(emailId) {
    const modal = document.getElementById('emailDetailsModal');
    const modalContent = document.getElementById('emailDetailsContent');
    
    if (!modal || !modalContent) return;
    
    // Show loading state
    modalContent.innerHTML = `
        <div class="text-center">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    // Show the modal
    const modalInstance = new bootstrap.Modal(modal);
    modalInstance.show();
    
    // In a real implementation, we would fetch the email details from the server
    // For now, we'll simulate with a timeout
    setTimeout(() => {
        modalContent.innerHTML = `
            <div class="alert alert-info">
                Email details for ID ${emailId} would be displayed here.
                This would include recipient information, delivery status, tracking events, etc.
            </div>
            <div class="mb-3">
                <h6>No data available</h6>
                <p>This is a placeholder. In a production environment, detailed email information would be retrieved from the server.</p>
            </div>
        `;
    }, 1000);
}

/**
 * Update chart based on selected period
 * @param {string} period - Selected period (week or month)
 */
function updateChartPeriod(period) {
    // In a real implementation, this would update the chart data
    console.log(`Chart period updated to: ${period}`);
}

/**
 * Truncate text to a specified length and add ellipsis
 * @param {string} text - Text to truncate
 * @param {number} maxLength - Maximum length before truncation
 * @returns {string} - Truncated text
 */
function truncateText(text, maxLength) {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

/**
 * Format a date string to a human-readable format
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date string
 */
function formatDate(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Initialize the page when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the dashboard if we're on that page
    if (document.getElementById('recentEmailsTable')) {
        initDashboard();
    }
    
    // Add event listeners for authentication forms if they exist
    const loginForm = document.querySelector('form[action="/login"]');
    if (loginForm) {
        // We don't need to add event listeners here since the form submits directly to the server
        // This is handled by Flask routes
    }
});
