import re
import math
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import urlparse

from scamshield.detection.brand_signals import (
    BRANDS,
    HIGH_RISK_TLDS,
    SUSPICIOUS_HOSTNAME_PREFIXES,
)
from scamshield.services.fact_check_service import FactCheckService
from scamshield.services.image_forensics_service import ImageForensicsService

try:
    from PIL import Image, ImageChops, ImageFilter, ImageStat
except ImportError:  # Pillow is optional for non-media deployments.
    Image = None
    ImageChops = None
    ImageFilter = None
    ImageStat = None


URGENCY_TERMS = {
    "urgent", "immediately", "now", "today", "within 24 hours", "limited time",
    "last warning", "final notice", "act fast", "verify now", "blocked",
    "offer expires", "expires today", "claim now", "congratulations", "you won", "won",
}

SENSITIVE_TERMS = {
    "otp", "password", "pin", "cvv", "upi pin", "bank details", "aadhaar",
    "pan card", "card number", "login", "verify account", "kyc",
}

AUTHORITY_TERMS = {
    "rbi", "income tax", "police", "bank officer", "customer care", "hr team",
    "recruiter", "government", "official", "support team",
}

REWARD_TERMS = {
    "prize", "bonus", "cashback", "lottery", "refund", "free", "job offer",
    "salary", "investment", "double your money", "gift", "you won", "congratulations", "claim your prize", "claim",
}

THREAT_TERMS = {
    "account will be closed", "legal action", "arrest", "penalty", "suspended",
    "blocked permanently", "fine", "case filed",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "lnkd.in",
}

EMAIL_TERMS = {
    "dear customer", "account suspended", "verify your account", "click here",
    "security alert", "unauthorized login", "reset your password", "login to your account",
}

SMS_TERMS = {
    "delivery", "package", "customs", "otp", "upi", "bank update", "payment due",
    "failed transaction", "last chance", "confirm now", "one-time password",
}

NEWS_TERMS = {
    "breaking", "exclusive", "viral", "official statement", "claim", "fact check",
    "conspiracy", "shocking", "urgent update", "unconfirmed", "must read",
}

FALSE_FACT_CHECK_TERMS = (
    "false", "fake", "pants on fire", "misleading", "fabricated", "incorrect",
)
TRUE_FACT_CHECK_TERMS = ("true", "correct", "accurate")


def _contains_any(text, terms):
    lowered = text.lower()
    return [term for term in terms if term in lowered]


def _extract_urls(text):
    pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)"
    urls = re.findall(pattern, text)
    return [url.rstrip(".,;!?)\"]'") for url in urls]


def _risk_label(score):
    if score >= 75:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _recommended_action(score):
    if score >= 75:
        return (
            "Do not click links, do not share OTP or banking details, "
            "and report this immediately."
        )
    if score >= 55:
        return "Verify through the official app or website before taking any action."
    if score >= 35:
        return "Treat this as suspicious and confirm the sender through a trusted channel."
    return "No major scam signals found, but stay cautious with unknown senders."


def analyze_content(content, content_type="message"):
    text = (content or "").strip()
    if not text:
        return {"error": "Content is required"}

    indicators = []
    score = 8
    fact_check = {
        "checked": False,
        "matches_found": False,
        "verdicts": [],
        "error": "not_applicable",
    }

    urgency = _contains_any(text, URGENCY_TERMS)
    if urgency:
        score += min(40, len(urgency) * 12)
        indicators.append({
            "name": "Urgency manipulation",
            "detail": "Pushes the user to act quickly without proper verification.",
            "matches": urgency[:5],
        })

    sensitive = _contains_any(text, SENSITIVE_TERMS)
    if sensitive:
        score += min(28, len(sensitive) * 9)
        indicators.append({
            "name": "Sensitive information request",
            "detail": "Mentions credentials, OTP, KYC, card, or banking information.",
            "matches": sensitive[:5],
        })

    authority = _contains_any(text, AUTHORITY_TERMS)
    if authority:
        score += min(18, len(authority) * 6)
        indicators.append({
            "name": "Authority impersonation",
            "detail": "Claims to represent a bank, company, recruiter, or official body.",
            "matches": authority[:5],
        })

    rewards = _contains_any(text, REWARD_TERMS)
    if rewards:
        score += min(36, len(rewards) * 10)
        indicators.append({
            "name": "Reward or fake opportunity",
            "detail": "Uses prizes, refunds, jobs, or benefits to lower suspicion.",
            "matches": rewards[:5],
        })

    # Explicit high-weight signals for prize/lottery phrasing and currency mentions
    if re.search(r"\byou won\b|\bcongratulations\b|\bclaim your prize\b|\bwon\b", text, re.I):
        score += 30
        indicators.append({
            "name": "Prize/lottery wording",
            "detail": "Mentions winning or claiming prizes which is common in prize scams.",
            "matches": ["prize wording"],
        })

    if re.search(r"\u20B9|\brs\b|\brupees\b", text, re.I):
        score += 18
        indicators.append({
            "name": "Monetary incentive",
            "detail": "Mentions currency or monetary amounts which are often used in financial bait.",
            "matches": ["currency mention"],
        })

    threats = _contains_any(text, THREAT_TERMS)
    if threats:
        score += min(20, len(threats) * 10)
        indicators.append({
            "name": "Fear pressure",
            "detail": "Uses threat language to force an emotional response.",
            "matches": threats[:5],
        })

    urls = _extract_urls(text)
    url_findings = [analyze_url(url) for url in urls[:3]]
    if urls:
        score += 18
        indicators.append({
            "name": "External link present",
            "detail": "Scam messages often move users to fake login or payment pages.",
            "matches": urls[:3],
        })
        if any(item["risk_score"] >= 55 for item in url_findings):
            score += 24

    # If the text contains URL shorteners anywhere, increase risk substantially
    for short in SHORTENERS:
        if short in text.lower():
            score += 30
            indicators.append({
                "name": "URL shortener detected",
                "detail": "Shortened links hide final destinations and are commonly used in scams.",
                "matches": [short],
            })
            break

    # Synergy: urgency + reward signals amplify risk
    if urgency and rewards:
        score += 20

    if re.search(r"\b\d{6}\b", text):
        score += 12
        indicators.append({
            "name": "OTP-like number detected",
            "detail": "Six-digit codes are commonly abused in OTP fraud.",
            "matches": ["6-digit code"],
        })

    if content_type == "email":
        email_signals = _contains_any(text, EMAIL_TERMS)
        if email_signals:
            score += min(40, len(email_signals) * 10)
            indicators.append({
                "name": "Email phishing style",
                "detail": "The message contains email scam phrases like account suspension or password reset.",
                "matches": email_signals[:5],
            })
    elif content_type == "sms":
        sms_signals = _contains_any(text, SMS_TERMS)
        if sms_signals:
            score += min(22, len(sms_signals) * 7)
            indicators.append({
                "name": "SMS scam style",
                "detail": "The message contains SMS scam language such as delivery, customs, or payment prompts.",
                "matches": sms_signals[:5],
            })
    elif content_type == "news":
        news_signals = _contains_any(text, NEWS_TERMS)
        if news_signals:
            score += min(20, len(news_signals) * 6)
            indicators.append({
                "name": "Fake news style",
                "detail": "The text uses viral or sensational language common in misinformation.",
                "matches": news_signals[:5],
            })

        fact_check = FactCheckService().search_claims(text)
        if fact_check["matches_found"]:
            false_verdict = next(
                (
                    verdict for verdict in fact_check["verdicts"]
                    if any(
                        term in verdict["rating"].lower()
                        for term in FALSE_FACT_CHECK_TERMS
                    )
                ),
                None,
            )
            true_verdict = next(
                (
                    verdict for verdict in fact_check["verdicts"]
                    if any(
                        term in verdict["rating"].lower()
                        for term in TRUE_FACT_CHECK_TERMS
                    )
                ),
                None,
            )
            if false_verdict:
                score = max(score, 80)
                indicators.append({
                    "name": "Fact-check match: false claim",
                    "detail": (
                        f"Independently fact-checked as '{false_verdict['rating']}' "
                        f"by {false_verdict['publisher']}."
                    ),
                    "matches": [false_verdict["url"]],
                })
            elif true_verdict:
                score = min(score, 15)
                indicators.append({
                    "name": "Fact-check match: verified claim",
                    "detail": (
                        f"Independently fact-checked as '{true_verdict['rating']}' "
                        f"by {true_verdict['publisher']}."
                    ),
                    "matches": [true_verdict["url"]],
                })
        elif fact_check["checked"]:
            indicators.append({
                "name": "No independent fact-check found",
                "detail": (
                    "This claim has not been reviewed by a known fact-checking "
                    "organization; result is based on writing-style heuristics "
                    "only, not verified truth."
                ),
                "matches": [],
            })

    scam_probability = min(100, score)
    risk_level = _risk_label(scam_probability)
    classification = _build_text_classification(content_type, scam_probability)
    confidence = _build_text_confidence(scam_probability)

    return {
        "content_type": content_type,
        "classification": classification,
        "scam_probability": scam_probability,
        "risk_level": risk_level,
        "confidence": confidence,
        "summary": _build_summary(content_type, risk_level, indicators),
        "indicators": indicators or [{
            "name": "No strong scam pattern",
            "detail": (
                "The content does not show common urgency, credential, "
                "or impersonation signals."
            ),
            "matches": [],
        }],
        "urls": url_findings,
        "fact_check": fact_check,
        "recommended_action": _recommended_action(scam_probability),
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _build_summary(content_type, risk_level, indicators):
    if not indicators:
        return "No major scam indicators were detected in this content."

    context_phrase = {
        "email": "email",
        "sms": "SMS",
        "news": "news",
    }.get(content_type, "message")

    names = ", ".join(item["name"].lower() for item in indicators[:3])
    return f"{risk_level} risk: this {context_phrase} contains {names}."


def _build_text_classification(content_type, score):
    if content_type == "email":
        if score >= 55:
            return "Email Scam"
        if score >= 35:
            return "Suspicious Email"
        return "Likely Legitimate Email"
    if content_type == "sms":
        if score >= 55:
            return "SMS Scam"
        if score >= 35:
            return "Suspicious SMS"
        return "Likely Legitimate SMS"
    if content_type == "news":
        if score >= 55:
            return "Fake News"
        if score >= 35:
            return "Potential Misinformation"
        return "Likely Legitimate News"
    if score >= 55:
        return "Suspicious Content"
    if score >= 35:
        return "Potential Scam"
    return "Low Risk Content"


def _build_text_confidence(score):
    if score >= 80:
        return 92
    if score >= 60:
        return 78
    if score >= 40:
        return 62
    return 48


def _build_url_confidence(risk_score, trust_score):
    if risk_score >= 70:
        return 81
    if risk_score >= 50:
        return 68
    if trust_score >= 70:
        return 86
    return 55


def analyze_url(url):
    raw_url = (url or "").strip()
    if not raw_url:
        return {"error": "URL is required"}

    normalized = raw_url if re.match(r"^https?://", raw_url, re.I) else f"http://{raw_url}"
    parsed = urlparse(normalized)
    domain = parsed.netloc.lower()
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()

    indicators = []
    score = 5

    if parsed.scheme != "https":
        score += 18
        indicators.append("No HTTPS encryption")

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", domain):
        score += 24
        indicators.append("Uses raw IP address instead of domain")

    if len(raw_url) > 75:
        score += 12
        indicators.append("Very long URL")

    if "@" in raw_url:
        score += 18
        indicators.append("Contains @ symbol redirection trick")

    if domain.count(".") >= 3:
        score += 12
        indicators.append("Excessive subdomains")

    if "-" in domain:
        score += 8
        indicators.append("Hyphenated domain often used for impersonation")

    if any(shortener in domain for shortener in SHORTENERS):
        score += 18
        indicators.append("URL shortener hides final destination")

    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in HIGH_RISK_TLDS:
        score += 14
        indicators.append(f"Domain uses higher-risk TLD .{tld}")

    if any(prefix in hostname for prefix in SUSPICIOUS_HOSTNAME_PREFIXES):
        score += 12
        indicators.append("Hostname contains suspicious prefix (e.g. secure-, verify-)")

    registered_domain = ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname
    if any(brand in hostname and registered_domain != f"{brand}.com" for brand in BRANDS):
        score += 14
        indicators.append("Possible brand impersonation")

    if any(word in path for word in ("login", "verify", "kyc", "secure", "account", "payment")):
        score += 12
        indicators.append("Sensitive action words in URL path")

    risk_score = min(100, score)
    trust_score = max(0, 100 - risk_score)
    confidence = _build_url_confidence(risk_score, trust_score)

    return {
        "url": raw_url,
        "result": "Phishing" if risk_score >= 55 else "Suspicious" if risk_score >= 35 else "Safe",
        "risk_score": risk_score,
        "trust_score": trust_score,
        "risk_level": _risk_label(risk_score),
        "confidence": confidence,
        "danger_indicators": indicators or ["No major URL danger indicators found"],
        "explanation": _explain_url(risk_score, indicators),
        "recommended_action": _recommended_action(risk_score),
    }


def _explain_url(score, indicators):
    if not indicators:
        return "The URL structure looks normal based on the available checks."
    return f"The URL has {len(indicators)} warning signals: {', '.join(indicators[:4])}."


def is_phishing(url):
    return analyze_url(url)


def _image_entropy(image):
    histogram = image.histogram()
    total = sum(histogram)
    if not total:
        return 0

    entropy = 0
    for count in histogram:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def _variance(values):
    if not values:
        return 0
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def _analyze_image_pixels(file_bytes):
    if Image is None:
        return {}, [{
            "name": "Pixel engine unavailable",
            "detail": "Install Pillow to enable image-level forensic checks.",
        }], 0

    image = Image.open(BytesIO(file_bytes))
    image.load()
    rgb = image.convert("RGB")
    grayscale = image.convert("L")
    width, height = image.size
    exif = image.getexif()

    indicators = []
    score_delta = 0

    camera_tags = {271, 272, 305, 306, 36867}  # Make, Model, Software, DateTime, DateTimeOriginal
    present_tags = {tag for tag in camera_tags if exif.get(tag)}
    software = str(exif.get(305, "")).lower()

    if not exif:
        score_delta += 6
        indicators.append({
            "name": "No camera details found",
            "detail": (
                "The file does not show normal camera information. "
                "AI-made or edited images often miss this."
            ),
        })
    elif not ({271, 272, 36867} & present_tags):
        score_delta += 14
        indicators.append({
            "name": "Camera details look incomplete",
            "detail": "Some file details exist, but camera name or capture time is missing.",
        })
    else:
        score_delta -= 8
        indicators.append({
            "name": "Camera details found",
            "detail": (
                "The image has camera-like file details, but this alone "
                "does not prove it is real."
            ),
        })

    generator_software = [
        "midjourney", "stable diffusion", "dall", "comfyui",
        "automatic1111", "runway", "leonardo",
    ]
    if any(term in software for term in generator_software):
        score_delta += 50
        indicators.append({
            "name": "AI tool name found",
            "detail": "The file details mention a known AI image tool.",
        })

    sample = rgb.resize((min(320, width), min(320, height)))
    gray_sample = sample.convert("L")
    edge = gray_sample.filter(ImageFilter.FIND_EDGES)
    edge_stat = ImageStat.Stat(edge)
    edge_mean = edge_stat.mean[0]

    entropy = _image_entropy(sample)
    blur = gray_sample.filter(ImageFilter.GaussianBlur(radius=1.2))
    noise_image = ImageChops.difference(gray_sample, blur)
    noise_stat = ImageStat.Stat(noise_image)
    noise_level = noise_stat.stddev[0]

    colors = (
        sample.convert("P", palette=Image.Palette.ADAPTIVE, colors=96)
        .getcolors(maxcolors=40000)
        or []
    )
    color_variance = _variance([count for count, _ in colors])

    if entropy < 5.1:
        score_delta += 12
        indicators.append({
            "name": "Texture looks too simple",
            "detail": "Some parts of the image look smoother or simpler than normal camera photos.",
        })
    elif entropy > 7.25:
        score_delta -= 5
        indicators.append({
            "name": "Many natural details found",
            "detail": (
                "The image has many small details, which can happen in real "
                "photos and high-quality AI images."
            ),
        })

    if noise_level < 1.5:
        score_delta += 6
        indicators.append({
            "name": "Camera grain is weak",
            "detail": (
                "Real camera photos usually have tiny sensor grain. "
                "This image has very little."
            ),
        })
    elif noise_level > 10:
        score_delta -= 4
        indicators.append({
            "name": "Camera-like grain found",
            "detail": "Some natural-looking camera grain is present.",
        })

    if edge_mean < 8:
        score_delta += 5
        indicators.append({
            "name": "Edges look too smooth",
            "detail": (
                "Some borders in the image are very smooth, which can happen "
                "in AI-made images."
            ),
        })

    if color_variance > 800_000:
        score_delta += 8
        indicators.append({
            "name": "Colors look unusually grouped",
            "detail": "The color pattern is a little unusual and needs caution.",
        })

    metrics = {
        "width": width,
        "height": height,
        "entropy": round(entropy, 3),
        "edge_mean": round(edge_mean, 3),
        "noise_level": round(noise_level, 3),
        "color_cluster_variance": round(color_variance, 3),
        "has_exif": bool(exif),
    }
    return metrics, indicators, score_delta


def _blend_ml_probability(score, indicators, probability, signal_name):
    if probability >= 0.75:
        score = max(score, 80)
        indicators.append({
            "name": f"{signal_name} detected by ML classifier",
            "detail": (
                f"Independent AI image classifier estimates {probability * 100:.0f}% "
                f"probability of {signal_name.lower()}."
            ),
            "matches": [],
        })
    elif probability <= 0.15:
        score = min(score, 20)
        indicators.append({
            "name": f"{signal_name} unlikely by ML classifier",
            "detail": (
                f"Independent AI image classifier estimates only {probability * 100:.0f}% "
                f"probability of {signal_name.lower()}."
            ),
            "matches": [],
        })
    else:
        score += round(probability * 30)
        indicators.append({
            "name": f"{signal_name} probability is inconclusive",
            "detail": (
                f"Independent AI image classifier estimates {probability * 100:.0f}% "
                f"probability of {signal_name.lower()}; this is blended with forensic signals."
            ),
            "matches": [],
        })
    return score


def analyze_media_file(
    filename,
    mimetype,
    size_bytes,
    width=None,
    height=None,
    duration=None,
    file_bytes=None,
):
    name = (filename or "").lower()
    mimetype = (mimetype or "").lower()
    indicators = []
    score = 10

    is_video = mimetype.startswith("video/")
    is_image = mimetype.startswith("image/")

    if not is_image and not is_video:
        score += 20
        indicators.append({
            "name": "Unsupported media type",
            "detail": "The uploaded file does not look like a standard image or video format.",
        })

    if size_bytes < 40_000:
        score += 6
        indicators.append({
            "name": "File is very small",
            "detail": (
                "Small files can hide useful proof, so the result should "
                "be treated carefully."
            ),
        })

    forensic_metrics = {}
    ml_classifier = None

    if file_bytes and is_image:
        try:
            forensic_metrics, image_indicators, image_delta = _analyze_image_pixels(file_bytes)
            indicators.extend(image_indicators)
            score += image_delta
            width = forensic_metrics.get("width") or width
            height = forensic_metrics.get("height") or height
        except Exception:
            score += 8
            indicators.append({
                "name": "Image forensic read failed",
                "detail": "The file could not be fully decoded for pixel-level analysis.",
            })

        ml_result = ImageForensicsService().analyze_image(file_bytes, filename)
        if ml_result.get("checked"):
            ml_classifier = ml_result
            strong_ml_signal = False
            for probability, signal_name in (
                (ml_result.get("ai_generated_probability"), "AI-generation"),
                (ml_result.get("deepfake_probability"), "Deepfake manipulation"),
            ):
                if probability is not None:
                    strong_ml_signal = strong_ml_signal or probability >= 0.75
                    score = _blend_ml_probability(
                        score, indicators, probability, signal_name
                    )
            if strong_ml_signal:
                score = max(score, 80)

    if width and height:
        pixel_count = width * height
        if pixel_count < 350_000:
            score += 14
            indicators.append({
                "name": "Low picture quality",
                "detail": (
                    "Low-resolution images are harder to verify, so the "
                    "system becomes more cautious."
                ),
            })
        elif pixel_count > 8_000_000:
            score -= 4
            indicators.append({
                "name": "High picture quality",
                "detail": "A larger image gives more details to inspect.",
            })

    generator_terms = [
        "midjourney", "stable-diffusion", "stablediffusion", "dalle", "dall-e",
        "sora", "runway", "pika", "leonardo", "ai-generated", "generated",
    ]
    matched_terms = [term for term in generator_terms if term in name]
    if matched_terms:
        score += 38
        indicators.append({
            "name": "AI word found in file name",
            "detail": f"The file name contains: {', '.join(matched_terms[:3])}.",
        })

    if any(item["name"] == "AI tool name found" for item in indicators):
        score = max(score, 60)

    if is_video and duration:
        if duration < 3:
            score += 8
            indicators.append({
                "name": "Very short clip",
                "detail": (
                    "Short clips are common in synthetic samples and need "
                    "frame-level review."
                ),
            })
        elif duration > 60:
            score -= 3

    if is_video:
        indicators.append({
            "name": "Frame-level model recommended",
            "detail": (
                "Video upload is supported, but advanced deepfake detection "
                "requires sampling frames and running a trained video model."
            ),
        })

    if is_image and any(ext in name for ext in (".webp", ".png")):
        score += 10
        indicators.append({
            "name": "Image format needs caution",
            "detail": (
                "PNG or WebP images often come from editing tools, downloads, "
                "screenshots, or AI tools."
            ),
        })

    if size_bytes > 5_000_000:
        score -= 5
        indicators.append({
            "name": "Large file has more proof",
            "detail": "A bigger file usually gives more details to check.",
        })

    likelihood = max(3, min(97, score))
    confidence = "High" if width and height and size_bytes > 120_000 else "Medium"
    if size_bytes < 50_000:
        confidence = "Low"

    if likelihood >= 60:
        risk = "May be AI-made"
        simple_result = "Do not trust it yet"
    elif likelihood >= 35:
        risk = "Not sure"
        simple_result = "Check the source"
    else:
        risk = "Looks real"
        simple_result = "Still verify once"

    if not indicators:
        indicators.append({
            "name": "No big warning found",
            "detail": (
                "This scan did not find strong AI signs, but it cannot "
                "guarantee the image is real."
            ),
        })

    return {
        "filename": filename,
        "media_type": "Video" if is_video else "Image" if is_image else "Unknown",
        "ai_likelihood": likelihood,
        "authenticity_score": 100 - likelihood,
        "risk_level": risk,
        "simple_result": simple_result,
        "confidence": confidence,
        "dimensions": {"width": width, "height": height},
        "duration_seconds": duration,
        "forensic_metrics": forensic_metrics,
        "ml_classifier": ml_classifier,
        "indicators": indicators,
        "explanation": (
            "This scan checks file details and image patterns. "
            "It is cautious when camera proof is missing."
        ),
        "recommended_action": (
            "Do not forward or trust this media until you confirm where it came from."
        ),
    }
