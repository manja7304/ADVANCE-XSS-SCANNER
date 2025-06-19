import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, quote
import re
import time
from playwright.sync_api import sync_playwright
import html
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
import random
from fpdf import FPDF
from datetime import datetime
import socket
import os

# Initialize rich console
console = Console()


class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (XSS Scanner)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        self.vulnerable_urls = []
        self.total_tests = 0
        self.positive_tests = 0
        self.show_banner()
        self.start_time = time.time()

    def show_banner(self):
        banner = r"""
         _____  _____  _____ 
        |  __ \/ ____|/ ____|
        | |__) | (___ | (___   ___ __ _ _ __ 
        |  _  / \___ \ \___ \ / __/ _` | '_ \
        | | \ \ ____) |____) | (_| (_| | | | |
        |_|  \_\_____/|_____/ \___\__,_|_| |_|
        
        [bold red]Advanced XSS Scanner v3.0[/bold red]
        [bold blue]The Ultimate XSS Detection Tool[/bold blue]
        """
        console.print(Panel.fit(banner, style="bold green"))
        console.print(
            Panel.fit(
                f"[bold]Target:[/bold] {self.target_url}\n[bold]Started:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        )

    def load_payloads(self, payload_file):
        try:
            with open(f"payloads/{payload_file}", "r", encoding="utf-8") as f:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            console.print(
                f"[red]Error:[/red] Payload file 'payloads/{payload_file}' not found!"
            )
            return []
        except Exception as e:
            console.print(f"[red]Error loading payloads:[/red] {str(e)}")
            return []

    def is_payload_executed(self, response_text, payload):
        """Improved detection of executed payloads"""
        decoded_text = html.unescape(response_text)

        # Check for common XSS execution patterns
        execution_indicators = [
            r"<script[^>]*>.*?</script>",
            r"on\w+\s*=",
            r"javascript:",
            r"eval\s*\(",
            r"alert\s*\(",
            r"document\.\w+",
            r"window\.location",
            r"innerHTML\s*=",
            r"<iframe[^>]*>",
            r"<svg[^>]*onload=",
            r"<img[^>]*onerror=",
        ]

        # Check if payload appears unmodified (likely not executed)
        if payload in decoded_text:
            return False

        # Check for execution patterns
        for pattern in execution_indicators:
            if re.search(pattern, decoded_text, re.IGNORECASE):
                return True

        return False

    def scan_reflected_xss(self):
        self.total_tests = 0
        self.positive_tests = 0

        console.rule("[bold yellow]Reflected XSS Scan[/bold yellow]")

        # Common vulnerable parameters
        common_params = [
            "q",
            "search",
            "id",
            "name",
            "query",
            "term",
            "keyword",
            "user",
            "email",
            "address",
            "redirect",
            "url",
            "file",
        ]

        payloads = self.load_payloads("reflected_xss.txt")
        if not payloads:
            return

        custom_jobs = [
            {"param": "q", "payload": "<script>alert(1)</script>"},
            {"param": "search", "payload": "'\"><svg/onload=alert(1)>"},
            {"param": "id", "payload": "javascript:alert(1)"},
        ]

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            transient=True,
        ) as progress:
            task = progress.add_task(
                "[cyan]Testing parameters...",
                total=len(common_params) * len(payloads) + len(custom_jobs),
            )

            # Test common parameters with all payloads
            for param in common_params:
                for payload in payloads:
                    self.total_tests += 1
                    encoded_payload = quote(payload)
                    test_url = f"{self.target_url}?{param}={encoded_payload}"

                    try:
                        response = self.session.get(test_url, timeout=15)
                        response.raise_for_status()

                        if self.is_payload_executed(response.text, payload):
                            self.positive_tests += 1
                            console.print(
                                f"[!] [bold red blink]CONFIRMED Reflected XSS:[/bold red blink] [underline]{test_url}[/underline]",
                                style="bold",
                            )
                            self.vulnerable_urls.append(
                                {
                                    "type": "Reflected XSS",
                                    "url": test_url,
                                    "param": param,
                                    "payload": payload,
                                    "confidence": "High",
                                }
                            )
                            time.sleep(0.2)  # Visual pause
                    except Exception as e:
                        console.print(
                            f"[yellow]Warning:[/yellow] Error testing {test_url} - {str(e)}"
                        )

                    progress.update(task, advance=1)

            # Test custom job combinations
            for job in custom_jobs:
                self.total_tests += 1
                encoded_payload = quote(job["payload"])
                test_url = f"{self.target_url}?{job['param']}={encoded_payload}"

                try:
                    response = self.session.get(test_url, timeout=15)
                    if self.is_payload_executed(response.text, job["payload"]):
                        self.positive_tests += 1
                        console.print(
                            f"[!] [bold red blink]CONFIRMED Reflected XSS:[/bold red blink] [underline]{test_url}[/underline]",
                            style="bold",
                        )
                        self.vulnerable_urls.append(
                            {
                                "type": "Reflected XSS",
                                "url": test_url,
                                "param": job["param"],
                                "payload": job["payload"],
                                "confidence": "High",
                            }
                        )
                except Exception as e:
                    console.print(
                        f"[yellow]Warning:[/yellow] Error testing {test_url} - {str(e)}"
                    )

                progress.update(task, advance=1)

    def scan_dom_xss(self):
        console.rule("[bold yellow]DOM XSS Scan[/bold yellow]")
        payloads = self.load_payloads("dom_xss.txt")
        if not payloads:
            return

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            )
            page = context.new_page()

            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "[cyan]Testing DOM payloads...", total=len(payloads)
                )

                for payload in payloads:
                    self.total_tests += 1
                    test_url = f"{self.target_url}#{payload}"

                    try:
                        page.goto(test_url, timeout=20000)
                        page.wait_for_timeout(3000)  # Wait for JS execution

                        # Check for alert dialogs
                        dialog_triggered = False

                        def handle_dialog(dialog):
                            nonlocal dialog_triggered
                            dialog_triggered = True
                            dialog.accept()

                        page.on("dialog", handle_dialog)

                        # Check DOM for execution evidence
                        dom_content = page.evaluate(
                            "document.documentElement.innerHTML"
                        )
                        if (
                            self.is_payload_executed(dom_content, payload)
                            or dialog_triggered
                        ):
                            self.positive_tests += 1
                            console.print(
                                f"[!] [bold red blink]CONFIRMED DOM XSS:[/bold red blink] [underline]{test_url}[/underline]",
                                style="bold",
                            )
                            self.vulnerable_urls.append(
                                {
                                    "type": "DOM XSS",
                                    "url": test_url,
                                    "payload": payload,
                                    "confidence": (
                                        "High" if dialog_triggered else "Medium"
                                    ),
                                }
                            )
                            time.sleep(0.2)
                    except Exception as e:
                        console.print(
                            f"[yellow]Warning:[/yellow] Error testing {test_url} - {str(e)}"
                        )

                    progress.update(task, advance=1)

            browser.close()

    def scan_stored_xss(self):
        console.rule("[bold yellow]Stored XSS Scan[/bold yellow]")

        try:
            response = self.session.get(self.target_url, timeout=15)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            if not forms:
                console.print("[yellow]No forms found for Stored XSS testing[/yellow]")
                return

            payloads = self.load_payloads("stored_xss.txt")
            if not payloads:
                return

            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "[cyan]Testing forms...", total=len(forms) * len(payloads)
                )

                for form in forms:
                    form_details = self._get_form_details(form)

                    for payload in payloads:
                        self.total_tests += 1
                        data = {}
                        for input_tag in form_details["inputs"]:
                            if input_tag["type"] == "hidden":
                                data[input_tag["name"]] = input_tag["value"]
                            elif input_tag["type"] != "submit":
                                data[input_tag["name"]] = payload

                        try:
                            if form_details["method"] == "post":
                                response = self.session.post(
                                    urljoin(self.target_url, form_details["action"]),
                                    data=data,
                                    timeout=15,
                                )
                            else:
                                response = self.session.get(
                                    urljoin(self.target_url, form_details["action"]),
                                    params=data,
                                    timeout=15,
                                )

                            # Verify if payload persists
                            verify_response = self.session.get(
                                urljoin(self.target_url, form_details["action"])
                            )
                            if self.is_payload_executed(verify_response.text, payload):
                                self.positive_tests += 1
                                console.print(
                                    f"[!] [bold red blink]POTENTIAL Stored XSS in form at:[/bold red blink] {form_details['action']}",
                                    style="bold",
                                )
                                self.vulnerable_urls.append(
                                    {
                                        "type": "Stored XSS",
                                        "url": urljoin(
                                            self.target_url, form_details["action"]
                                        ),
                                        "form_action": form_details["action"],
                                        "payload": payload,
                                        "confidence": "High",
                                    }
                                )
                                time.sleep(0.2)

                        except Exception as e:
                            console.print(
                                f"[yellow]Warning:[/yellow] Error testing form - {str(e)}"
                            )

                        progress.update(task, advance=1)

        except Exception as e:
            console.print(f"[red]Error during Stored XSS scan:[/red] {str(e)}")

    def _get_form_details(self, form):
        details = {}
        details["action"] = form.attrs.get("action", "").lower()
        details["method"] = form.attrs.get("method", "get").lower()
        details["inputs"] = []

        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            details["inputs"].append(
                {"type": input_type, "name": input_name, "value": input_value}
            )

        return details

    def show_results(self):
        elapsed_time = time.time() - self.start_time
        console.rule("[bold green]Scan Results[/bold green]")

        # Summary Panel
        summary_table = Table(title="[bold]Scan Summary[/bold]", show_header=False)
        summary_table.add_row("Target URL", self.target_url)
        summary_table.add_row("Total Tests", str(self.total_tests))
        summary_table.add_row("Vulnerabilities Found", str(len(self.vulnerable_urls)))
        summary_table.add_row("Scan Duration", f"{elapsed_time:.2f} seconds")
        console.print(summary_table)

        if not self.vulnerable_urls:
            console.print(
                Panel.fit(
                    "[bold green]✓ No XSS vulnerabilities found![/bold green]",
                    style="green",
                )
            )
            return

        # Detailed Findings
        findings_table = Table(
            title="[bold red]XSS Vulnerabilities Found[/bold red]", expand=True
        )
        findings_table.add_column("Type", style="cyan")
        findings_table.add_column("Location", style="magenta")
        findings_table.add_column("Payload", style="yellow", no_wrap=True)
        findings_table.add_column("Confidence", justify="right")

        for vuln in self.vulnerable_urls:
            if vuln["type"] == "Stored XSS":
                location = f"Form at: {vuln['form_action']}"
            else:
                location = vuln["url"]

            findings_table.add_row(
                vuln["type"],
                location,
                (
                    vuln["payload"][:50] + "..."
                    if len(vuln["payload"]) > 50
                    else vuln["payload"]
                ),
                f"[bold]{vuln['confidence']}[/bold]",
            )

        console.print(findings_table)

        # Generate PDF Report
        self.generate_pdf_report(elapsed_time)

    def generate_pdf_report(self, elapsed_time):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)

        # Header
        pdf.cell(0, 10, "XSS Vulnerability Scan Report", 0, 1, "C")
        pdf.ln(10)

        # Scan Info
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Target URL: {self.target_url}", 0, 1)
        pdf.cell(
            0, 10, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1
        )
        pdf.cell(0, 10, f"Scan Duration: {elapsed_time:.2f} seconds", 0, 1)
        pdf.cell(0, 10, f"Total Tests: {self.total_tests}", 0, 1)
        pdf.cell(0, 10, f"Vulnerabilities Found: {len(self.vulnerable_urls)}", 0, 1)
        pdf.ln(10)

        # Findings
        if self.vulnerable_urls:
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Vulnerability Details:", 0, 1)
            pdf.set_font("Arial", "", 10)

            for vuln in self.vulnerable_urls:
                pdf.set_fill_color(255, 230, 230)
                pdf.cell(0, 10, f"Type: {vuln['type']}", 0, 1, fill=True)
                if vuln["type"] == "Stored XSS":
                    pdf.cell(0, 10, f"Form Action: {vuln['form_action']}", 0, 1)
                else:
                    pdf.cell(0, 10, f"URL: {vuln['url']}", 0, 1)
                pdf.cell(0, 10, f"Payload: {vuln['payload']}", 0, 1)
                pdf.cell(0, 10, f"Confidence: {vuln['confidence']}", 0, 1)
                pdf.ln(5)
        else:
            pdf.cell(0, 10, "No vulnerabilities found.", 0, 1)

        # Footer
        pdf.set_y(-15)
        pdf.set_font("Arial", "I", 8)
        pdf.cell(0, 10, f"Generated by Advanced XSS Scanner v3.0", 0, 0, "C")

        # Save report
        report_filename = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf.output(report_filename)
        console.print(
            f"\n[bold]PDF report generated:[/bold] [underline]{report_filename}[/underline]"
        )


if __name__ == "__main__":
    try:
        console.print("\n")
        target = console.input(
            "[bold yellow]Enter target URL (e.g., http://example.com): [/bold yellow]"
        )

        # Validate URL format
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        scanner = XSSScanner(target)

        with console.status(
            "[bold green]Scanning target...[/bold green]", spinner="dots"
        ):
            scanner.scan_reflected_xss()
            scanner.scan_dom_xss()
            scanner.scan_stored_xss()

        scanner.show_results()

    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user![/red]")
    except Exception as e:
        console.print(f"\n[red]Fatal error:[/red] {str(e)}")
