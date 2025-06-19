import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.text import Text
import time

# Initialize rich console
console = Console()


class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerable_urls = []
        self.show_banner()

    def show_banner(self):
        banner = """
        ███████╗██╗  ██╗███████╗
        ╚══███╔╝╚██╗██╔╝██╔════╝
          ███╔╝  ╚███╔╝ ███████╗
         ███╔╝   ██╔██╗ ╚════██║
        ███████╗██╔╝ ██╗███████║
        ╚══════╝╚═╝  ╚═╝╚══════╝
        [bold red]Advanced XSS Scanner[/bold red]
        """
        console.print(Panel.fit(banner, style="bold blue"))

    def load_payloads(self, payload_file):
        with open(f"payloads/{payload_file}", "r") as f:
            return [line.strip() for line in f]

    def scan_reflected_xss(self):
        console.rule("[bold yellow]Reflected XSS Scan[/bold yellow]")
        params = {"q": "test", "search": "query"}
        payloads = self.load_payloads("reflected_xss.txt")

        with Progress() as progress:
            task = progress.add_task(
                "[cyan]Testing parameters...", total=len(params) * len(payloads)
            )

            for param in params:
                for payload in payloads:
                    test_url = f"{self.target_url}?{param}={payload}"
                    response = self.session.get(test_url)
                    progress.update(task, advance=1)

                    if payload in response.text:
                        console.print(
                            f"[!] [bold red]Possible Reflected XSS:[/bold red] [underline]{test_url}[/underline]",
                            style="blink",
                        )
                        self.vulnerable_urls.append(test_url)
                        time.sleep(0.5)  # Dramatic pause

    def scan_dom_xss(self):
        console.rule("[bold yellow]DOM XSS Scan[/bold yellow]")
        from playwright.sync_api import sync_playwright

        payloads = self.load_payloads("dom_xss.txt")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            with Progress() as progress:
                task = progress.add_task(
                    "[cyan]Testing DOM payloads...", total=len(payloads)
                )

                for payload in payloads:
                    test_url = f"{self.target_url}#{payload}"
                    page.goto(test_url)
                    progress.update(task, advance=1)

                    try:
                        page.wait_for_timeout(2000)
                        if page.evaluate(
                            "document.documentElement.innerHTML.includes('alert')"
                        ):
                            console.print(
                                f"[!] [bold red]Possible DOM XSS:[/bold red] [underline]{test_url}[/underline]",
                                style="blink",
                            )
                            self.vulnerable_urls.append(test_url)
                            time.sleep(0.5)  # Dramatic pause
                    except:
                        pass

            browser.close()

    def show_results(self):
        console.rule("[bold green]Scan Results[/bold green]")
        if not self.vulnerable_urls:
            console.print("[bold green]✓ No XSS vulnerabilities found![/bold green]")
        else:
            table = Table(title="[bold red]XSS Vulnerabilities Found[/bold red]")
            table.add_column("Type", style="cyan")
            table.add_column("URL", style="magenta")

            for url in self.vulnerable_urls:
                if "#" in url:
                    table.add_row("DOM XSS", url)
                else:
                    table.add_row("Reflected XSS", url)

            console.print(table)


if __name__ == "__main__":
    console.print("\n")
    target = console.input("[bold yellow]Enter target URL: [/bold yellow]")
    scanner = XSSScanner(target)

    with console.status("[bold green]Scanning target...[/bold green]", spinner="dots"):
        scanner.scan_reflected_xss()
        scanner.scan_dom_xss()

    scanner.show_results()
