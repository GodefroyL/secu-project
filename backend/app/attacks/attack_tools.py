"""
Utility functions for security attack simulations.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
from uuid import uuid4

import requests
from bs4 import BeautifulSoup

from app.models import Asset, Evidence, Finding, Severity

DEFAULT_SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    '" OR "a"="a',
    "admin' --",
]

SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql",
    r"sqlite",
    r"psql",
    r"postgres",
    r"ora-\d{5}",
    r"syntax error",
]

COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("test", "test"),
    ("user", "password"),
    ("demo", "demo"),
]

@dataclass
class FormSpec:
    """Represents a form extracted from an HTML page.

    Attributes:
        action (str): The URL where the form is submitted.
        method (str): The HTTP method used to submit the form (e.g., "post", "get").
        inputs (list[dict[str, str]]): A list of dictionaries, each representing an input field.
    """
    action: str
    method: str
    inputs: list[dict[str, str]]

def make_id(prefix: str) -> str:
    """Generate a unique identifier for findings.

    Args:
        prefix (str): A prefix to prepend to the generated ID.

    Returns:
        str: A unique identifier.
    """
    return f"{prefix}-{uuid4().hex[:8]}"

def get_forms(target_url: str) -> tuple[list[FormSpec], bool]:
    """Extract all forms from a given URL.

    Args:
        target_url (str): The URL to extract forms from.

    Returns:
        tuple[list[FormSpec], bool]: A list of forms and a boolean indicating if the request succeeded.
    """
    try:
        response = requests.get(target_url, timeout=5)
    except requests.RequestException:
        return [], False

    soup = BeautifulSoup(response.text, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = (form.get("action") or "").strip()
        action_url = urljoin(response.url, action) if action else response.url

        inputs = []
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").strip()
            input_type = (inp.get("type") or "text").lower()
            if name:
                inputs.append({"name": name, "type": input_type})

        forms.append(FormSpec(action=action_url, method=method, inputs=inputs))

    return forms, True

def looks_like_login_success(response: requests.Response, baseline: requests.Response | None) -> bool:
    """Determine if a response resembles a successful login.

    Args:
        response (requests.Response): The response to evaluate.
        baseline (requests.Response | None): The baseline response for comparison.

    Returns:
        bool: True if the response resembles a successful login, False otherwise.
    """
    if response.status_code in {401, 403}:
        return False

    body = response.text.lower()
    if any(token in body for token in ["logout", "dashboard", "welcome", "account"]):
        return True

    if baseline is None:
        return False

    delta = abs(len(response.text) - len(baseline.text))
    return response.status_code == 200 and delta > max(200, int(len(baseline.text) * 0.2))

def get_urls_from_sitemap(target_url: str) -> list[str]:
    """Extract URLs from a sitemap.xml file.

    Args:
        target_url (str): The base URL to derive the sitemap URL.

    Returns:
        list[str]: A list of URLs extracted from the sitemap.
    """
    try:
        parsed = urlparse(target_url)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        response = requests.get(sitemap_url, timeout=5)
    except requests.RequestException:
        return []

    if response.status_code != 200:
        return []

    try:
        root = ET.fromstring(response.content)
    except ET.ParseError:
        return []

    namespace = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    urls = []
    for url in root.findall("ns:url", namespace):
        loc = url.find("ns:loc", namespace)
        if loc is not None and loc.text:
            urls.append(loc.text)
    return urls
