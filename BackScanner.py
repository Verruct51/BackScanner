import requests
import re
import time
import fitz  # PyMuPDF
import pytesseract
from PIL import Image
from io import BytesIO
from termcolor import colored
from colorama import init

init()

def ascii_art():
    print(colored(r"""
 ____             _     _____                                 
|  _ \           | |   / ____|                                
| |_) | __ _  ___| | _| (___   ___ __ _ _ __  _ __   ___ _ __ 
|  _ < / _` |/ __| |/ /\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |_) | (_| | (__|   < ____) | (_| (_| | | | | | | |  __/ |   
|____/ \__,_|\___|_|\_\_____/ \___\__,_|_| |_|_| |_|\___|_|   

    """, "cyan"))

def load_keywords(path):
    keywords = set()
    try:
        with open(path, 'r') as f:
            for line in f:
                word = line.strip().lower()
                if word:
                    keywords.add(word)
    except Exception as e:
        print(colored(f"[ERROR] Gagal membaca wordlist: {e}", "red"))
    return list(keywords)

def get_wayback_timestamps(pdf_url):
    try:
        cdx_params = {
            'url': pdf_url,
            'output': 'json',
            'filter': 'statuscode:200',
            'fl': 'timestamp'
        }
        res = requests.get('https://web.archive.org/cdx/search/cdx', params=cdx_params, timeout=10)
        if res.status_code == 200:
            timestamps = [entry[0] for entry in res.json()[1:]]
            return timestamps
    except Exception as e:
        print(colored(f"[ERROR] Gagal ambil timestamp Wayback: {e}", "red"))
    return []

def extract_text_fallback(content):
    try:
        images = []
        doc = fitz.open(stream=content, filetype='pdf')
        for page in doc:
            pix = page.get_pixmap(dpi=300)
            img = Image.open(BytesIO(pix.tobytes('png')))
            images.append(img)

        text = ""
        for img in images:
            text += pytesseract.image_to_string(img)

        return text.lower()
    except Exception as e:
        print(colored(f"[OCR FAIL] {e}", "red"))
        return ""

def extract_text_from_pdf(content):
    try:
        doc = fitz.open(stream=content, filetype="pdf")
        text = ""
        for page in doc:
            text += page.get_text()
        return text.lower()
    except:
        return extract_text_fallback(content)

def check_sensitive_data(text, keywords):
    pattern = r'\b(?:' + '|'.join(map(re.escape, keywords)) + r')\b'
    return re.findall(pattern, text)

def request_with_backoff(url, max_retries=3, base_delay=2):
    for attempt in range(max_retries):
        try:
            res = requests.get(url, timeout=15)
            if res.status_code == 200:
                return res
        except requests.RequestException as e:
            wait = base_delay * (2 ** attempt)
            print(colored(f"[RETRY-{attempt+1}] Gagal akses, tunggu {wait}s: {e}", "yellow"))
            time.sleep(wait)
    print(colored(f"[SKIP] Gagal akses URL setelah {max_retries} percobaan: {url}", "red"))
    return None

def process_pdf(pdf_url, keywords, output_file, delay_between_requests=10):
    timestamps = get_wayback_timestamps(pdf_url)
    for ts in timestamps:
        wayback_url = f"https://web.archive.org/web/{ts}/{pdf_url}"
        print(colored(f"[SCAN] {wayback_url}", "green"))

        res = request_with_backoff(wayback_url)
        if not res:
            continue

        if 'application/pdf' not in res.headers.get('Content-Type', ''):
            print(colored("[SKIP] Bukan file PDF valid", "yellow"))
            continue

        text = extract_text_from_pdf(res.content)
        matches = check_sensitive_data(text, keywords)

        if matches:
            print(colored("[!] Sensitive data FOUND!", "red"))
            print(colored(f"    Keywords: {', '.join(matches)}", "yellow"))
            with open(output_file, 'a') as f:
                f.write(f"URL: {wayback_url}\n")
                f.write(f"Keywords: {', '.join(matches)}\n")
                f.write("-" * 50 + "\n")

        time.sleep(delay_between_requests)

def main():
    ascii_art()
    pdf_list_path = input(colored("Masukkan path file daftar PDF: ", "blue"))
    wordlist_path = input(colored("Masukkan path wordlist: ", "blue"))
    output_file = "VULN.txt"

    keywords = load_keywords(wordlist_path)
    if not keywords:
        print(colored("[!] Tidak ada keyword yang dimuat.", "red"))
        return

    try:
        with open(pdf_list_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(colored(f"[ERROR] Gagal membaca file PDF list: {e}", "red"))
        return

    with open(output_file, 'w') as f:
        f.write("HASIL PEMINDAIAN BACKSCANNER\n")
        f.write("=" * 50 + "\n")

    for i, url in enumerate(urls, 1):
        print(colored(f"Memproses [{i}/{len(urls)}]: {url}", "cyan"))
        process_pdf(url, keywords, output_file)

    print(colored(f"\n✅ Pemindaian selesai. Hasil disimpan di {output_file}", "green"))

if __name__ == "__main__":
    main()
