import requests
from bs4 import BeautifulSoup


class XSSCrawler:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.forms = []

    def crawl_forms(self):
        response = self.session.get(self.target_url)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            form_details = {
                "action": form.get("action"),
                "method": form.get("method", "get").lower(),
                "inputs": [input.get("name") for input in form.find_all("input")],
            }
            self.forms.append(form_details)

    def test_stored_xss(self):
        payloads = self.load_payloads("stored_xss.txt")

        for form in self.forms:
            for payload in payloads:
                data = {input_name: payload for input_name in form["inputs"]}

                if form["method"] == "post":
                    response = self.session.post(
                        urljoin(self.target_url, form["action"]), data=data
                    )
                else:
                    response = self.session.get(
                        urljoin(self.target_url, form["action"]), params=data
                    )

                if payload in response.text:
                    print(f"[!] Possible Stored XSS in form at {form['action']}")
