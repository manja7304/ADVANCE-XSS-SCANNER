from fpdf import FPDF


class PDFReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, "XSS Vulnerability Report", 0, 1, "C")

    def add_finding(self, url, vulnerability_type):
        self.set_font("Arial", "", 10)
        self.cell(0, 10, f"URL: {url}", 0, 1)
        self.cell(0, 10, f"Type: {vulnerability_type}", 0, 1)
        self.ln(5)


def generate_report(vulnerabilities):
    pdf = PDFReport()
    pdf.add_page()

    for vuln in vulnerabilities:
        pdf.add_finding(vuln["url"], vuln["type"])

    pdf.output("xss_report.pdf")
