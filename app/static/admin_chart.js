// Draws the bar chart of login risk levels on the admin page with Chart.js.
// The server puts the counts in the canvas's data-counts attribute.

const riskCanvas = document.getElementById("risk-chart");
const riskCounts = JSON.parse(riskCanvas.dataset.counts);

new Chart(riskCanvas, {
    type: "bar",
    data: {
        labels: ["low", "medium", "high"],
        datasets: [{
            label: "Logins",
            data: [riskCounts.low, riskCounts.medium, riskCounts.high],
            backgroundColor: ["#2e7d32", "#f9a825", "#c62828"],
        }],
    },
    options: {
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
});
