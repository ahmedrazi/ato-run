#!/usr/bin/env python3
"""ATO Run: a terminal simulator of the FedRAMP authorization lifecycle.

Simplified training model. Remediation windows use the classic Rev5
30/90/180-day timelines, rounded to months. Check fedramp.gov for current rules.
"""
import os
import random
import sys
import textwrap
from dataclasses import dataclass, field

PHASES = ["Prepare", "Document", "Assess", "Authorize", "Monitor"]
SLA = {"H": 1, "M": 3, "L": 6}  # months
SEV = {"H": "High", "M": "Moderate", "L": "Low"}
CAPACITY = 4       # items the team can close per monitoring month
CONMON_MONTHS = 6
EVENT_MONTH = 3

ASSESS_POOL = {
    "H": ["Admin console reachable without MFA",
          "Customer data replicated outside the boundary",
          "Critical CVE on the bastion host"],
    "M": ["Audit log retention below agency requirement",
          "Stale service accounts never disabled",
          "FIPS-validated crypto not enforced on internal TLS",
          "Incident response plan never tested",
          "Configuration drift on worker nodes",
          "No inventory of container image components"],
    "L": ["Login banner missing on SSH",
          "Asset inventory missing three hosts",
          "Security training records incomplete",
          "Password policy document out of date"],
}
SCAN_POOL = {
    "H": ["Critical CVE in base container image",
          "Management port exposed on load balancer",
          "Remote code execution in web framework"],
    "M": ["Node OS missing security patches",
          "Weak TLS cipher enabled on ingress",
          "Library with known CVE in API service",
          "Outdated OpenSSL on worker nodes"],
    "L": ["Security header missing on web app",
          "Verbose error pages",
          "Outdated package with no known exploit"],
}


@dataclass
class Item:
    sev: str
    name: str
    id: str = ""
    age: int = 0
    late: bool = False


@dataclass
class State:
    month: int = 0
    spent: int = 0          # $k
    quality: int = 40
    trust: int = 60
    path: str = ""          # "rev5" or "20x"
    findings: list = field(default_factory=list)
    authorized: bool = False
    ato_month: int = 0
    ato_spent: int = 0
    cm_month: int = 0
    vulns: list = field(default_factory=list)
    late: int = 0
    fixed: int = 0
    shipped: int = 0
    next_id: int = 0
    event_done: bool = False

    def add(self, month=0, spent=0, quality=0, trust=0):
        self.month += month
        self.spent += spent
        self.quality += quality
        self.trust += trust

    def count(self, sev):
        return sum(1 for f in self.findings if f.sev == sev)


def clamp(n, lo, hi):
    return max(lo, min(hi, n))


# ---------------------------------------------------------------- mechanics

def generate_findings(s, rng):
    q = clamp(s.quality, 0, 100)
    n = {
        "H": 0 if q >= 75 else 1 if q >= 55 else 2 if q >= 35 else 3,
        "M": clamp(round((100 - q) / 12), 1, 6),
        "L": clamp(round((100 - q) / 15) + 1, 1, 4),
    }
    s.findings = [Item(sev, name) for sev in "HML"
                  for name in rng.sample(ASSESS_POOL[sev], n[sev])]


def new_item(s, sev, name):
    s.next_id += 1
    return Item(sev, name, id=f"V-{s.next_id}")


def spawn(s, n, rng):
    for _ in range(n):
        r = rng.random()
        sev = "H" if r < .15 else "M" if r < .6 else "L"
        s.vulns.append(new_item(s, sev, rng.choice(SCAN_POOL[sev])))


def tick(s, strategy, rng):
    """Advance one monitoring month. strategy: 'sev', 'age', or 'skip'."""
    rank = {"H": 0, "M": 1, "L": 2}
    closed = 0
    if strategy == "skip":
        s.shipped += 1
    else:
        if strategy == "sev":
            s.vulns.sort(key=lambda v: (rank[v.sev], -v.age))
        else:
            s.vulns.sort(key=lambda v: -v.age)
        closed = len(s.vulns[:CAPACITY])
        del s.vulns[:CAPACITY]
        s.fixed += closed

    new_late = 0
    for v in s.vulns:
        v.age += 1
        if not v.late and v.age >= SLA[v.sev]:
            v.late = True
            new_late += 1
            s.late += 1
            s.trust -= 8 if v.sev == "H" else 3

    s.cm_month += 1
    s.month += 1
    if s.cm_month < CONMON_MONTHS:
        spawn(s, 2 + rng.randrange(3), rng)

    first = ("Your team shipped roadmap work instead of patching."
             if strategy == "skip"
             else f"Closed {closed} item{'' if closed == 1 else 's'}.")
    second = (f"{new_late} item{'' if new_late == 1 else 's'} went past due, "
              "and the agency noticed." if new_late else "Nothing went past due.")
    return f"{first} {second}"


def final_score(s):
    score = (100 - max(0, s.ato_month - 12) * 3 - s.late * 5
             - max(0, (s.ato_spent - 900) / 50) + (s.trust - 60) / 2 + s.shipped * 2)
    score = round(clamp(score, 0, 100))
    if s.trust < 25:
        verdict = "The agency suspends use pending corrective action"
    elif score >= 80:
        verdict = "Authorization in good standing"
    elif score >= 55:
        verdict = "Authorized, with an uneasy agency"
    else:
        verdict = "Authorization at risk"
    return score, verdict


# ---------------------------------------------------------------- scenes
# Each scene: (phase, title, text, [(label, desc, effect)]); effect(s, rng) -> message

def scene_intro(s):
    return (0, "Your agency sponsor is waiting",
            "You lead platform engineering at Northwind, a SaaS provider. A federal "
            "agency wants your product at a Moderate impact level and has agreed to "
            "sponsor you. Get authorized, then keep the authorization.",
            [("Start the run", "", lambda s, r: "")])


def scene_path(s):
    def rev5(s, r):
        s.path = "rev5"
        return ("You picked the familiar path, but you're investing in a process "
                "FedRAMP is retiring.")

    def x20(s, r):
        s.path = "20x"
        return ("Review moves faster when evidence is automated. This path rewards "
                "cloud-native, IaC-heavy stacks and punishes manual evidence.")

    return (0, "Choose your authorization path",
            "Rev5 is the document-based path agencies know. FedRAMP 20x replaces "
            "narratives with Key Security Indicators backed by automated evidence.",
            [("Legacy Rev5", "Control narratives, sponsor-driven review. New Rev5 "
              "applications close June 11, 2027.", rev5),
             ("FedRAMP 20x", "Key Security Indicators validated continuously.", x20)])


def scene_boundary(s):
    def tight(s, r):
        s.add(month=1, quality=15)
        return ("A smaller boundary means fewer controls to prove and fewer places "
                "for the assessor to find problems.")

    def broad(s, r):
        s.add(quality=-15)
        return ("You just multiplied the evidence you owe. Every system in scope "
                "carries the full control set.")

    return (0, "Draw the authorization boundary",
            "Everything inside the boundary has to meet every applicable control.",
            [("Scope only the production SaaS stack",
              "Corporate IT stays out. Costs a month of data-flow mapping.", tight),
             ("Include everything that touches the product",
              "Corporate laptops, ticketing, the office network.", broad)])


def scene_hosting(s):
    def inherit(s, r):
        s.add(month=1, spent=100, quality=15)
        return ("Inheritance takes whole control families, like physical security, "
                "off your plate.")

    def colo(s, r):
        s.add(month=3, spent=250, quality=-5)
        msg = "You now own physical, environmental, and hardware controls end to end."
        if s.path == "20x":
            s.add(quality=-10)
            msg += (" 20x is built around cloud-native services; self-run "
                    "infrastructure is one of the cases where FedRAMP still points "
                    "providers to Rev5.")
        return msg

    return (0, "Decide where the product runs",
            "Hosting decides how many controls you can inherit.",
            [("An IaaS that's already FedRAMP authorized",
              "Inherit physical and infrastructure controls. Hosting costs more.", inherit),
             ("Your own colocated hardware",
              "Cheaper per unit, but every control is yours.", colo)])


def scene_readiness(s):
    def advisor(s, r):
        s.add(month=2, spent=150, quality=15)
        return "Gaps surfaced early, while fixing them was still cheap."

    def diy(s, r):
        s.add(month=4, spent=40, quality=3)
        return ("Cheaper and slower, and you missed the gaps you didn't know to "
                "look for.")

    return (0, "Run a readiness gap assessment",
            "Find out how far you are from the baseline before an assessor does.",
            [("Hire an advisory firm", "$150k and two months.", advisor),
             ("Do it in-house from the baseline",
              "About $40k of staff time and four months.", diy)])


def scene_package(s):
    def with_assessment(fn):
        def effect(s, r):
            msg = fn(s)
            s.add(month=3, spent=300)
            generate_findings(s, r)
            return msg
        return effect

    if s.path == "rev5":
        def manual(s):
            s.add(month=5, spent=80, quality=5)
            return ("Accurate on the day it was written, stale by the next deploy. "
                    "The 2026 Consolidated Rules are moving Rev5 away from static "
                    "documents toward machine-readable data.")

        def oscal(s):
            s.add(month=3, spent=120, quality=12)
            return ("Your documentation tracks the real system, and you're ahead on "
                    "the machine-readable requirements coming to Rev5.")

        return (1, "Build the authorization package",
                "Your sponsor and assessor need to see how every control is implemented.",
                [("Write control narratives by hand", "Five months of writing.",
                  with_assessment(manual)),
                 ("Generate documentation from IaC and OSCAL",
                  "Tooling investment up front, three months.", with_assessment(oscal))])

    def ksi(s):
        s.add(month=2, spent=150, quality=20)
        return "Every pipeline run now produces fresh evidence."

    def screenshots(s):
        s.add(month=1, spent=30, quality=-20)
        return ("Point-in-time evidence is exactly what 20x was built to replace. "
                "Expect pushback.")

    return (1, "Build your evidence pipeline",
            "20x reviewers expect Key Security Indicators backed by evidence from "
            "the running system.",
            [("Wire KSI validations into CI/CD", "Two months and $150k of engineering.",
              with_assessment(ksi)),
             ("Collect screenshots and exports", "Fast and cheap.",
              with_assessment(screenshots))])


def scene_assess(s):
    def fix_first(s, r):
        s.add(month=2, spent=80, trust=10)
        s.findings = [f for f in s.findings if f.sev != "H"]
        mods = [f for f in s.findings if f.sev == "M"]
        drop = mods[:(len(mods) + 1) // 2]
        s.findings = [f for f in s.findings if f not in drop]
        return "Findings closed before the report don't follow you into authorization."

    def submit(s, r):
        s.add(trust=-5)
        if s.count("H"):
            return "Open high findings are a red flag for any authorizing official."
        return "Reasonable, since nothing high is open."

    text = (f"Assessment took three months and $300k. The assessor found "
            f"{s.count('H')} high, {s.count('M')} moderate, and {s.count('L')} "
            f"low findings.")
    return (2, "The 3PAO assessment is in", text,
            [("Fix highs and half the moderates before the report",
              "Two more months and $80k.", fix_first),
             ("Submit the report as-is with a remediation plan",
              "No added time.", submit)])


def scene_authorize(s):
    if s.count("H"):
        def resubmit(s, r):
            s.add(month=2, spent=60, trust=-10)
            s.findings = [f for f in s.findings if f.sev != "H"]
            return "Highs closed. The delay cost you some goodwill with your sponsor."
        n = s.count("H")
        return (3, "The agency sends the package back",
                f"The authorizing official won't accept risk with {n} open high "
                f"finding{'' if n == 1 else 's'}.",
                [("Fix the highs and resubmit", "Two months and $60k.", resubmit)])

    def decide(s, r):
        months = 4 if s.path == "rev5" else 2
        s.add(month=months)
        s.authorized = True
        s.ato_month, s.ato_spent = s.month, s.spent
        s.vulns = [new_item(s, f.sev, f.name) for f in s.findings]
        spawn(s, 3, r)
        return (f"Review took {months} months. AUTHORIZED. That took {s.ato_month} "
                f"months and ${s.ato_spent}k. {len(s.findings)} open findings carry "
                f"into continuous monitoring.")

    return (3, "Agency review",
            "The authorizing official reviews your package and the remaining findings.",
            [("Request the authorization decision", "", decide)])


def scene_event(s):
    def file_scr(s, r):
        s.event_done = True
        s.add(trust=5)
        return ("The agency approves after review. Slower, but your authorization "
                "stays clean.")

    def ship(s, r):
        s.event_done = True
        s.shipped += 1
        s.add(trust=-30)
        return ("The agency found out from a scan. Unreported significant changes "
                "are how providers lose their authorization.")

    return (4, "A product team wants to ship an AI assistant",
            "It adds a new external service and a new data flow inside the boundary. "
            "That's a significant change.",
            [("File a significant change request and wait",
              "The feature waits for agency approval.", file_scr),
             ("Ship it now and tell the agency later",
              "The feature goes out this month.", ship)])


def scene_month(s):
    return (4, f"Monitoring month {s.cm_month + 1} of {CONMON_MONTHS}",
            f"Your team can close {CAPACITY} items this month. "
            f"Open items: {len(s.vulns)}.",
            [("Close highs first, then the oldest", "",
              lambda s, r: tick(s, "sev", r)),
             ("Close the oldest items first", "", lambda s, r: tick(s, "age", r)),
             ("Skip patching and ship the roadmap",
              "Good for the business, bad for your due dates.",
              lambda s, r: tick(s, "skip", r))])


def play(io, rng):
    s = State()
    for scene in (scene_intro, scene_path, scene_boundary, scene_hosting,
                  scene_readiness, scene_package, scene_assess):
        io.run(s, rng, scene(s))
    while not s.authorized:
        io.run(s, rng, scene_authorize(s))
    while s.cm_month < CONMON_MONTHS:
        if s.cm_month == EVENT_MONTH and not s.event_done:
            io.run(s, rng, scene_event(s))
        else:
            io.run(s, rng, scene_month(s))
    io.final(s)
    return s


# ---------------------------------------------------------------- terminal UI

class Terminal:
    def __init__(self):
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        if color and os.name == "nt":
            os.system("")  # enable ANSI escape handling on Windows 10+
        c = (lambda code: f"\033[{code}m") if color else (lambda code: "")
        self.bold, self.dim, self.reset = c("1"), c("2"), c("0")
        self.sev_color = {"H": c("31;1"), "M": c("33;1"), "L": c("2")}
        self.accent, self.green = c("34;1"), c("32;1")
        self.width = min(80, max(50, _term_width()))

    def wrap(self, text, indent=""):
        return textwrap.fill(text, self.width, initial_indent=indent,
                             subsequent_indent=indent)

    def meters(self, s):
        track = "  ".join(
            f"{self.green}[x] {p}{self.reset}" if i < self.phase
            else f"{self.accent}[>] {p}{self.reset}" if i == self.phase
            else f"{self.dim}[ ] {p}{self.reset}"
            for i, p in enumerate(PHASES))
        print(track)
        spent = s.ato_spent if s.authorized else s.spent
        print(f"{self.dim}Months {s.month}  |  Spent to authorize ${spent}k  |  "
              f"Package quality {clamp(s.quality, 0, 100)}  |  "
              f"Agency trust {clamp(s.trust, 0, 100)}{self.reset}")

    def table(self, items, with_age):
        if not items:
            print("  No open items.")
            return
        for v in items:
            sev = f"{self.sev_color[v.sev]}{SEV[v.sev]:<9}{self.reset}"
            if with_age:
                due = (f"{self.sev_color['H']}PAST DUE{self.reset}" if v.late
                       else f"due in {SLA[v.sev] - v.age} mo")
                print(f"  {v.id:<6} {sev} {v.name:<45} {v.age} mo  {due}")
            else:
                print(f"  {sev} {v.name}")

    def run(self, s, rng, scene):
        self.phase, title, text, options = scene
        print("\n" + "=" * self.width)
        self.meters(s)
        print(f"\n{self.accent}Phase {self.phase + 1}: {PHASES[self.phase]}{self.reset}")
        print(f"{self.bold}{title}{self.reset}")
        print(self.wrap(text))
        if title.startswith("The 3PAO"):
            self.table(s.findings, with_age=False)
        elif title.startswith("Monitoring"):
            self.table(s.vulns, with_age=True)
        print()
        for i, (label, desc, _) in enumerate(options, 1):
            print(f"  {self.bold}{i}){self.reset} {label}")
            if desc:
                print(f"{self.dim}{self.wrap(desc, indent='     ')}{self.reset}")
        choice = self.ask(len(options))
        msg = options[choice][2](s, rng)
        if msg:
            print("\n" + self.wrap(msg, indent="  > "))
            input(f"{self.dim}\nPress Enter to continue...{self.reset}")

    def ask(self, n):
        if n == 1:
            input(f"\nPress Enter to choose 1... ")
            return 0
        while True:
            raw = input(f"\nChoose 1-{n}: ").strip()
            if raw.isdigit() and 1 <= int(raw) <= n:
                return int(raw) - 1
            print(f"Please enter a number from 1 to {n}.")

    def final(self, s):
        score, verdict = final_score(s)
        print("\n" + "=" * self.width)
        print(f"{self.bold}FINAL REPORT: {verdict}{self.reset}\n")
        rows = [
            ("Score", f"{score} / 100"),
            ("Path", "Rev5" if s.path == "rev5" else "FedRAMP 20x"),
            ("Months to authorization", s.ato_month),
            ("Spent before authorization", f"${s.ato_spent}k"),
            ("Items closed in monitoring", s.fixed),
            ("Items that went past due", s.late),
            ("Months spent on roadmap", s.shipped),
            ("Agency trust", clamp(s.trust, 0, 100)),
        ]
        for k, v in rows:
            print(f"  {k:<28} {v}")
        print()


def _term_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def main():
    ui = Terminal()
    print(f"{ui.bold}ATO Run{ui.reset}: take a SaaS product from zero to a FedRAMP "
          "authorization, then keep it.")
    print(f"{ui.dim}Simplified training model. Check fedramp.gov for current "
          f"rules. Ctrl+C to quit.{ui.reset}")
    try:
        while True:
            play(ui, random.Random())
            if input("Play again? [y/N] ").strip().lower() != "y":
                break
    except (KeyboardInterrupt, EOFError):
        print("\nBye.")
    # Keep the window open when double-clicked on Windows.
    if os.name == "nt" and not os.environ.get("PROMPT"):
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
