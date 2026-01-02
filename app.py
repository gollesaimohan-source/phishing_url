from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__, static_folder="frontend", template_folder="frontend", static_url_path="")
CORS(app)
from detector import is_phishing

@app.route("/")
def index():
    return render_template("index.html")

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
