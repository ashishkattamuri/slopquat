"""Fixture app: imports a stdlib module, a famous package, and two
import-name traps (cv2, bs4)."""

import os
import sys
import numpy as np
import cv2
from bs4 import BeautifulSoup
import requests


def scrape(url: str) -> str:
    resp = requests.get(url, timeout=10)
    return BeautifulSoup(resp.text, "html.parser").get_text()