let riskChartInstance = null;

function checkURL() {
    const urlInput = document.getElementById("urlInput");
    const resultText = document.getElementById("resultText");
    const resultContainer = document.getElementById("resultContainer");
    const visitBtn = document.getElementById("visitBtn");
    const loading = document.getElementById("loading");

    const url = urlInput.value.trim();

    if (!url) {
        alert("Please enter a valid URL!");
        return;
    }

    // UI Reset
    resultContainer.classList.add("hidden");
    loading.classList.remove("hidden");
    visitBtn.classList.add("hidden");

    fetch("/check-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
    })
        .then(response => response.json())
        .then(data => {
            loading.classList.add("hidden");
            resultContainer.classList.remove("hidden");

            const riskScore = data.risk_score;
            // Heuristic: Higher score = more phishing features
            // Normalize score (assuming max around 5-7 for visualization)
            const safeScore = Math.max(0, 10 - riskScore);
            const dangerScore = riskScore;

            const isPhishing = data.result === "Phishing";

            // Update Text
            if (isPhishing) {
                resultText.innerHTML = `<span style="color: #ff4d4d">🚫 Dangerous Site Detected</span>`;
                visitBtn.innerText = "Visit Anyway (Unsafe)";
                visitBtn.style.borderColor = "#ff4d4d";
                visitBtn.style.color = "#ff4d4d";
            } else {
                resultText.innerHTML = `<span style="color: #00b894">✅ Safe to Visit</span>`;
                visitBtn.innerText = "Visit Site";
                visitBtn.style.borderColor = "#00b894";
                visitBtn.style.color = "#00b894";
            }

            // Update Button Link
            // Ensure URL has protocol for anchor tag
            let cleanUrl = url.startsWith('http') ? url : 'http://' + url;
            visitBtn.href = cleanUrl;
            visitBtn.classList.remove("hidden");

            // Update Chart
            updateChart(safeScore, dangerScore);
        })
        .catch(err => {
            loading.classList.add("hidden");
            alert("Error connecting to server. Is it running?");
            console.error(err);
        });
}

function updateChart(safe, danger) {
    const ctx = document.getElementById('riskChart').getContext('2d');

    if (riskChartInstance) {
        riskChartInstance.destroy();
    }

    riskChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Safety Confidence', 'Phishing Risk'],
            datasets: [{
                data: [safe, danger],
                backgroundColor: [
                    '#00b894', // Safe Green
                    '#ff4d4d'  // Danger Red
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#fff' }
                }
            }
        }
    });
}
