/**
 * Charts JavaScript file for the Enterprise SMTP Server
 * Handles all chart rendering and interactions on the dashboard
 */

// Color palette for charts
const chartColors = {
    primary: '#3498db',
    success: '#2ecc71',
    danger: '#e74c3c',
    warning: '#f39c12',
    info: '#3498db',
    secondary: '#95a5a6',
    background: 'rgba(52, 73, 94, 0.1)', // Dark blue with transparency
    gridLines: 'rgba(255, 255, 255, 0.1)'
};

// Global chart instances
let activityChart = null;
let statusChart = null;

/**
 * Initialize the email activity chart
 * @param {Object} dailyData - Daily email statistics data
 */
function initEmailActivityChart(dailyData) {
    const ctx = document.getElementById('emailActivityChart');
    if (!ctx) return;

    // Process data for chart
    const labels = [];
    const values = [];

    // Sort dates and get the last 7 days
    const sortedDates = Object.keys(dailyData).sort();
    const recentDates = sortedDates.slice(-7);

    // Create data arrays
    recentDates.forEach(date => {
        // Format date for display
        const dateParts = date.split('-');
        const displayDate = `${dateParts[1]}/${dateParts[2]}`;
        
        labels.push(displayDate);
        values.push(dailyData[date] || 0);
    });

    // Chart configuration
    const config = {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Emails Sent',
                data: values,
                backgroundColor: chartColors.primary,
                borderColor: chartColors.primary,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: chartColors.gridLines
                    },
                    ticks: {
                        precision: 0
                    }
                },
                x: {
                    grid: {
                        color: chartColors.gridLines
                    }
                }
            },
            plugins: {
                tooltip: {
                    mode: 'index',
                    intersect: false
                },
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            animation: {
                duration: 1000
            }
        }
    };

    // Destroy previous chart instance if it exists
    if (activityChart) {
        activityChart.destroy();
    }

    // Create new chart
    activityChart = new Chart(ctx, config);
}

/**
 * Initialize the email status pie chart
 * @param {Object} statusData - Email status breakdown data
 */
function initStatusChart(statusData) {
    const ctx = document.getElementById('statusChart');
    if (!ctx) return;

    // Process data for chart
    const labels = [];
    const values = [];
    const backgroundColors = [];

    // Map status to colors
    const statusColors = {
        'sent': chartColors.success,
        'queued': chartColors.warning,
        'failed': chartColors.danger,
        'delivered': chartColors.primary,
        'bounced': chartColors.secondary
    };

    // Create data arrays
    for (const status in statusData) {
        labels.push(status.charAt(0).toUpperCase() + status.slice(1)); // Capitalize first letter
        values.push(statusData[status]);
        backgroundColors.push(statusColors[status] || chartColors.secondary);
    }

    // Handle empty data
    if (values.length === 0) {
        labels.push('No Data');
        values.push(1);
        backgroundColors.push(chartColors.secondary);
    }

    // Chart configuration
    const config = {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: backgroundColors,
                borderColor: 'rgba(255, 255, 255, 0.2)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '70%',
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    };

    // Destroy previous chart instance if it exists
    if (statusChart) {
        statusChart.destroy();
    }

    // Create new chart
    statusChart = new Chart(ctx, config);
}

/**
 * Update the email activity chart with new data
 * @param {Object} newData - New email activity data
 */
function updateEmailActivityChart(newData) {
    if (!activityChart) return;
    
    // Process new data
    const labels = [];
    const values = [];
    
    // Sort dates and get recent ones
    const sortedDates = Object.keys(newData).sort();
    const recentDates = sortedDates.slice(-7);
    
    // Create data arrays
    recentDates.forEach(date => {
        // Format date for display
        const dateParts = date.split('-');
        const displayDate = `${dateParts[1]}/${dateParts[2]}`;
        
        labels.push(displayDate);
        values.push(newData[date] || 0);
    });
    
    // Update chart data
    activityChart.data.labels = labels;
    activityChart.data.datasets[0].data = values;
    
    // Update the chart
    activityChart.update();
}

/**
 * Update the status chart with new data
 * @param {Object} newData - New status breakdown data
 */
function updateStatusChart(newData) {
    if (!statusChart) return;
    
    // Process new data
    const labels = [];
    const values = [];
    const backgroundColors = [];
    
    // Map status to colors
    const statusColors = {
        'sent': chartColors.success,
        'queued': chartColors.warning,
        'failed': chartColors.danger,
        'delivered': chartColors.primary,
        'bounced': chartColors.secondary
    };
    
    // Create data arrays
    for (const status in newData) {
        labels.push(status.charAt(0).toUpperCase() + status.slice(1)); // Capitalize first letter
        values.push(newData[status]);
        backgroundColors.push(statusColors[status] || chartColors.secondary);
    }
    
    // Handle empty data
    if (values.length === 0) {
        labels.push('No Data');
        values.push(1);
        backgroundColors.push(chartColors.secondary);
    }
    
    // Update chart data
    statusChart.data.labels = labels;
    statusChart.data.datasets[0].data = values;
    statusChart.data.datasets[0].backgroundColor = backgroundColors;
    
    // Update the chart
    statusChart.update();
}

/**
 * Fetch new chart data from the server and update charts
 */
function refreshChartData() {
    // Get email statistics from the API
    getEmailStats()
        .then(data => {
            // Update charts with new data
            updateEmailActivityChart(data.daily_stats || {});
            updateStatusChart(data.status_breakdown || {});
        })
        .catch(error => {
            console.error('Error refreshing chart data:', error);
        });
}

// Export functions for use in other scripts
window.initEmailActivityChart = initEmailActivityChart;
window.initStatusChart = initStatusChart;
window.updateEmailActivityChart = updateEmailActivityChart;
window.updateStatusChart = updateStatusChart;
window.refreshChartData = refreshChartData;
