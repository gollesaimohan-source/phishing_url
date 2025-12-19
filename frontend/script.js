function checkURL() {
    const url = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");

    if (url.trim() === "") {
        resultDiv.innerText = "Please enter a URL";
        resultDiv.style.color = "orange";
        return;
    }

    resultDiv.innerText = "Analyzing URL...";
    resultDiv.style.color = "#203a43";

    fetch("http://127.0.0.1:5000/check-url", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        if (data.result === "Phishing") {
            resultDiv.innerHTML = `
                🚫 <strong>Phishing URL</strong><br>
                Risk Score: ${data.risk_score}
            `;
            resultDiv.style.color = "red";
        } else {
            resultDiv.innerHTML = `
                ✅ <strong>Safe URL</strong><br>
                Risk Score: ${data.risk_score}
            `;
            resultDiv.style.color = "green";
        }

        // Risk bar update (if present)
        const riskFill = document.getElementById("riskFill");
        if (riskFill) {
            let percentage = (data.risk_score / 5) * 100;
            riskFill.style.width = percentage + "%";

            if (data.risk_score <= 1) {
                riskFill.style.background = "green";
            } else if (data.risk_score <= 3) {
                riskFill.style.background = "orange";
            } else {
                riskFill.style.background = "red";
            }
        }
    })
    .catch(error => {
        resultDiv.innerText = "Error connecting to server";
        resultDiv.style.color = "red";
        console.error(error);
    });
}
