

import pandas as pd
import numpy as np
from scipy.io import arff
from urllib.parse import urlparse
import socket
import requests
from bs4 import BeautifulSoup
import whois
import tldextract
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib



dataset_path = r"c:/DSA/arrays/nielit/Training Dataset.arff"   # change if needed

data, meta = arff.loadarff(dataset_path)
df = pd.DataFrame(data)


df = df.astype(int)

print("\n📌 Dataset Loaded Successfully!")
print("Shape:", df.shape)
print("Columns:", list(df.columns))

# Split features & label
X = df.drop(columns=["Result"])
y = df["Result"]


feature_names = list(X.columns)

scaler = StandardScaler()
scaler.fit(X.values)
X_scaled = scaler.transform(X.values)


X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)


rf_model = RandomForestClassifier(n_estimators=300, random_state=42)
rf_model.fit(X_train, y_train)
y_pred = rf_model.predict(X_test)

print("\n🎯 Random Forest Performance:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

# Save model & scaler
joblib.dump(rf_model, r"c:/DSA/arrays/nielit/phishing_rf_model_30feat.pkl")
joblib.dump(scaler, r"c:/DSA/arrays/nielit/scaler_30feat.pkl")
print("\n📁 Model & Scaler Saved Successfully!")


# ==========================
# 3️⃣ HELPER FUNCTIONS FOR URL FEATURES
# ==========================

def get_domain(url):
    return urlparse(url).netloc

def get_response(url):
    try:
        return requests.get(url, timeout=5)
    except:
        return None

def having_IP_Address(url):
    try:
        domain = get_domain(url)
        socket.inet_aton(domain)
        return 1
    except:
        return -1

def URL_Length(url):
    length = len(url)
    if length < 54:
        return 1
    elif 54 <= length <= 75:
        return 0
    else:
        return -1

def Shortining_Service(url):
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "is.gd", "ow.ly"]
    return -1 if any(s in url for s in shorteners) else 1

def having_At_Symbol(url):
    return -1 if "@" in url else 1

def double_slash_redirecting(url):
    # search '//' after protocol
    pos = url.find("//", 7)
    return -1 if pos != -1 else 1

def Prefix_Suffix(url):
    domain = get_domain(url)
    return -1 if "-" in domain else 1

def having_Sub_Domain(url):
    domain = get_domain(url)
    dots = domain.count(".")
    if dots <= 1:
        return 1
    elif dots == 2:
        return 0
    else:
        return -1

def SSLfinal_State(url):
    # Very simplified: https = 1, http = -1
    if url.startswith("https"):
        return 1
    else:
        return -1

def Domain_registeration_length(url):
    try:
        domain = get_domain(url)
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if exp is None:
            return -1
        today = datetime.now()
        length = (exp - today).days
        # >= 1 year considered safe
        return 1 if length >= 365 else -1
    except:
        return -1

def Favicon(url):
    try:
        response = get_response(url)
        if response is None:
            return -1
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("link", rel=lambda x: x and "icon" in x.lower()):
            href = link.get("href", "")
            if get_domain(href) and get_domain(href) != get_domain(url):
                return -1
        return 1
    except:
        return -1

def port(url):
    domain = urlparse(url).netloc
    if ":" in domain:
        try:
            port_num = int(domain.split(":")[1])
            if port_num in [80, 443]:
                return 1
            else:
                return -1
        except:
            return -1
    return 1

def HTTPS_token(url):
    domain = get_domain(url)
    return -1 if "https" in domain or "http" in domain else 1

def Request_URL(url):
    try:
        response = get_response(url)
        if response is None:
            return -1
        soup = BeautifulSoup(response.text, "html.parser")
        domain = get_domain(url)
        total = 0
        external = 0

        tags = soup.find_all(["img", "audio", "embed", "iframe"])
        for tag in tags:
            src = tag.get("src")
            if src:
                total += 1
                if domain not in src:
                    external += 1

        if total == 0:
            return 1
        ratio = external / total
        if ratio < 0.22:
            return 1
        elif ratio <= 0.61:
            return 0
        else:
            return -1
    except:
        return -1

def URL_of_Anchor(url):
    try:
        response = get_response(url)
        if response is None:
            return -1
        soup = BeautifulSoup(response.text, "html.parser")
        anchors = soup.find_all("a")
        domain = get_domain(url)
        if len(anchors) == 0:
            return 1
        unsafe = 0
        for a in anchors:
            href = a.get("href")
            if href is None or href == "#" or href.startswith("#") or "javascript" in href.lower():
                unsafe += 1
            elif domain not in href:
                unsafe += 1
        ratio = unsafe / len(anchors)
        if ratio < 0.31:
            return 1
        elif ratio <= 0.67:
            return 0
        else:
            return -1
    except:
        return -1

def Links_in_tags(url):
    try:
        response = get_response(url)
        if response is None:
            return -1
        soup = BeautifulSoup(response.text, "html.parser")
        domain = get_domain(url)
        tags = soup.find_all(["meta", "script", "link"])
        total = len(tags)
        external = 0
        for tag in tags:
            for attr in ["href", "src", "content"]:
                link = tag.get(attr)
                if link and domain not in link:
                    external += 1
                    break
        if total == 0:
            return 1
        ratio = external / total
        if ratio < 0.17:
            return 1
        elif ratio <= 0.81:
            return 0
        else:
            return -1
    except:
        return -1

def SFH(url):
    try:
        response = get_response(url)
        if response is None:
            return -1
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        domain = get_domain(url)
        if len(forms) == 0:
            return 1
        for form in forms:
            action = form.get("action")
            if action is None or action == "" or action.lower() == "about:blank":
                return -1
            elif domain not in action:
                return 0
        return 1
    except:
        return -1

def Submitting_to_email(url):
    try:
        response = get_response(url)
        if response is None:
            return 1
        if "mailto:" in response.text:
            return -1
        return 1
    except:
        return 1

def Abnormal_URL(url):
    try:
        domain = get_domain(url)
        w = whois.whois(domain)
        if w.domain_name is None:
            return -1
        return 1
    except:
        return -1

def Redirect(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        if response is None:
            return 0
        n_redirects = len(response.history)
        if n_redirects <= 1:
            return 1
        elif n_redirects < 4:
            return 0
        else:
            return -1
    except:
        return 0

def on_mouseover(url):
    try:
        response = get_response(url)
        if response is None:
            return 1
        if "onmouseover" in response.text.lower():
            return -1
        return 1
    except:
        return 1

def RightClick(url):
    try:
        response = get_response(url)
        if response is None:
            return 1
        text = response.text.lower()
        if "event.button==2" in text or "contextmenu" in text:
            return -1
        return 1
    except:
        return 1

def popUpWidnow(url):
    try:
        response = get_response(url)
        if response is None:
            return 1
        if "window.open(" in response.text:
            return -1
        return 1
    except:
        return 1

def Iframe(url):
    try:
        response = get_response(url)
        if response is None:
            return 1
        soup = BeautifulSoup(response.text, "html.parser")
        if len(soup.find_all("iframe")) > 0:
            return -1
        return 1
    except:
        return 1

def age_of_domain(url):
    try:
        domain = get_domain(url)
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return -1
        days = (datetime.now() - creation).days
        # >= 6 months
        return 1 if days >= 180 else -1
    except:
        return -1

def DNSRecord(url):
    try:
        domain = get_domain(url)
        socket.gethostbyname(domain)
        return 1
    except:
        return -1

def web_traffic(url):
    # Can't access Alexa here; use neutral 0
    return 0

def Page_Rank(url):
    # Placeholder, neutral
    return 0

def Google_Index(url):
    # Placeholder, neutral
    return 0

def Links_pointing_to_page(url):
    try:
        response = get_response(url)
        if response is None:
            return 0
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a")
        n = len(links)
        if n == 0:
            return -1
        elif n < 2:
            return 0
        else:
            return 1
    except:
        return 0

def Statistical_report(url):
    # Very simple heuristic: suspicious TLD or keyword
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
    suspicious_words = ["login", "verify", "update", "secure", "bank", "free"]
    domain = get_domain(url).lower()
    ext = tldextract.extract(url)
    tld = "." + ext.suffix if ext.suffix else ""
    if any(tld == s for s in suspicious_tlds):
        return -1
    if any(word in domain for word in suspicious_words):
        return -1
    return 1


# ==========================
# 4️⃣ MAIN FEATURE BUILDER (URL → 30 FEATURES)
# ==========================

def extract_features_from_url(url: str) -> list:
    """
    Build dict of all 30 feature values,
    then return them in the SAME ORDER as training data columns.
    """
    feats = {}

    # Map each dataset feature name to function:
    feats["having_IP_Address"]           = having_IP_Address(url)
    feats["URL_Length"]                  = URL_Length(url)
    feats["Shortining_Service"]          = Shortining_Service(url)
    feats["having_At_Symbol"]           = having_At_Symbol(url)
    feats["double_slash_redirecting"]    = double_slash_redirecting(url)
    feats["Prefix_Suffix"]               = Prefix_Suffix(url)
    feats["having_Sub_Domain"]           = having_Sub_Domain(url)
    feats["SSLfinal_State"]              = SSLfinal_State(url)
    feats["Domain_registeration_length"] = Domain_registeration_length(url)
    feats["Favicon"]                     = Favicon(url)
    feats["port"]                        = port(url)
    feats["HTTPS_token"]                 = HTTPS_token(url)
    feats["Request_URL"]                 = Request_URL(url)
    feats["URL_of_Anchor"]               = URL_of_Anchor(url)
    feats["Links_in_tags"]               = Links_in_tags(url)
    feats["SFH"]                         = SFH(url)
    feats["Submitting_to_email"]         = Submitting_to_email(url)
    feats["Abnormal_URL"]                = Abnormal_URL(url)
    feats["Redirect"]                    = Redirect(url)
    feats["on_mouseover"]                = on_mouseover(url)
    feats["RightClick"]                  = RightClick(url)
    feats["popUpWidnow"]                 = popUpWidnow(url)
    feats["Iframe"]                      = Iframe(url)
    feats["age_of_domain"]               = age_of_domain(url)
    feats["DNSRecord"]                   = DNSRecord(url)
    feats["web_traffic"]                 = web_traffic(url)
    feats["Page_Rank"]                   = Page_Rank(url)
    feats["Google_Index"]                = Google_Index(url)
    feats["Links_pointing_to_page"]      = Links_pointing_to_page(url)
    feats["Statistical_report"]          = Statistical_report(url)

    # Now create feature vector in the SAME order as training columns
    feature_vector = [feats.get(name, 0) for name in feature_names]
    return feature_vector


# ==========================
# 5️⃣ PREDICTION FUNCTION
# ==========================

def check_url(url: str) -> str:
    vec = extract_features_from_url(url)
    vec = np.array(vec).reshape(1, -1)
    vec_scaled = scaler.transform(vec)
    pred = rf_model.predict(vec_scaled)[0]
    # In this dataset: -1 = phishing, 1 = legitimate
    if pred == -1:
        return "🚫 Phishing URL"
    else:
        return "✔ Safe URL"


# ==========================
# 6️⃣ QUICK TEST + USER LOOP
# ==========================







while True:
    user_url = input("\nEnter URL (or 'exit' to stop): ")
    if user_url.lower().strip() == "exit":
        print("Exiting... ✅")
        break
    print("Result:", check_url(user_url.strip()))
