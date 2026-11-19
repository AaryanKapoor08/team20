// Draws the bar chart of login risk levels on the admin page with Chart.js.
// The server puts the counts in the canvas's data-counts attribute.
// The whole site is black, white and grey, so the three bars differ by shade:
// light grey for low, mid grey for medium, near black for high.

const riskCanvas = document.getElementById("risk-chart");
const riskCounts = JSON.parse(riskCanvas.dataset.counts);

const INK = "#09090b";
const MUTED = "#71717a";
const LINE = "#e4e4e7";
const MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

new Chart(riskCanvas, {
    type: "bar",
    data: {
        labels: ["low", "medium", "high"],
        datasets: [{
            label: "Logins",
            data: [riskCounts.low, riskCounts.medium, riskCounts.high],
            backgroundColor: ["#d4d4d8", "#a1a1aa", "#3f3f46"],
            borderRadius: 6,
            borderSkipped: false,
            maxBarThickness: 64,
        }],
    },
    options: {
        aspectRatio: 1.9,
        // The bars are drawn once and then left alone, so the page settles
        // straight away and a screenshot of it is always the finished chart.
        animation: false,
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: INK,
                padding: 10,
                cornerRadius: 6,
                displayColors: false,
                bodyFont: { family: MONO },
            },
        },
        scales: {
            // Only faint lines across the chart, and no box around it.
            y: {
                beginAtZero: true,
                border: { display: false },
                grid: { color: LINE },
                ticks: { precision: 0, color: MUTED, font: { family: MONO, size: 11 } },
            },
            x: {
                grid: { display: false },
                border: { color: LINE },
                ticks: { color: MUTED, font: { family: MONO, size: 11 } },
            },
        },
    },
});
