from flask import Flask, render_template, request
from urllib.parse import urlparse
import re

app = Flask(__name__)

def check_phishing(url):
    reasons = []
    score = 0

    parsed = urlparse(url)
    domain = parsed.netloc

    if not url.startswith("https://"):
        score += 1
        reasons.append("URL does not use HTTPS")

    if len(url) > 75:
        score += 1
        reasons.append("URL is very long")

    if "@" in url:
        score += 1
        reasons.append("URL contains @ symbol")

    if "-" in domain:
        score += 1
        reasons.append("Domain contains hyphen")

    if domain.count(".") > 2:
        score += 1
        reasons.append("Domain has too many dots")

    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 1
        reasons.append("URL uses IP address instead of domain name")

    suspicious_words = ["login", "verify", "update", "free", "gift", "bank", "password", "secure"]
    for word in suspicious_words:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains suspicious word: {word}")

    if score >= 3:
        result = "Phishing / Suspicious"
    else:
        result = "Safe"

    return result, reasons


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    reasons = []

    if request.method == "POST":
        url = request.form["url"]
        result, reasons = check_phishing(url)

    return render_template("index.html", result=result, reasons=reasons)


if __name__ == "__main__":
    app.run(debug=True)