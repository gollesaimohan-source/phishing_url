from flask import Flask, request, jsonify
from flask_cors import CORS
from detector import is_phishing

app = Flask(__name__)
CORS(app)

@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"]
    result = is_phishing(url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
