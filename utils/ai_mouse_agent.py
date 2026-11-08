# utils/ai_mouse_agent.py
import asyncio
import base64
import hashlib
import io
import json
import math
import os
import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable
from urllib.parse import urlparse, urljoin


class AgentState(Enum):
    IDLE = "idle"
    NAVIGATING = "navigating"
    ANALYZING = "analyzing"
    INTERACTING = "interacting"
    SOLVING_CAPTCHA = "solving_captcha"
    EXTRACTING = "extracting"
    COMPLETE = "complete"
    FAILED = "failed"


class ElementType(Enum):
    INPUT_TEXT = "input_text"
    INPUT_PASSWORD = "input_password"
    INPUT_EMAIL = "input_email"
    BUTTON_SUBMIT = "button_submit"
    BUTTON_CLICK = "button_click"
    CHECKBOX = "checkbox"
    SELECT = "select"
    LINK = "link"
    CAPTCHA_IMAGE = "captcha_image"
    CAPTCHA_CHECKBOX = "captcha_checkbox"
    MFA_INPUT = "mfa_input"
    UNKNOWN = "unknown"


class ActionType(Enum):
    MOVE = "move"
    CLICK = "click"
    DOUBLE_CLICK = "double_click"
    RIGHT_CLICK = "right_click"
    TYPE = "type"
    CLEAR_TYPE = "clear_type"
    SCROLL = "scroll"
    HOVER = "hover"
    WAIT = "wait"
    KEY_PRESS = "key_press"
    SCREENSHOT = "screenshot"
    NAVIGATE = "navigate"


class InteractionResult(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    CAPTCHA_DETECTED = "captcha_detected"
    MFA_REQUIRED = "mfa_required"
    RATE_LIMITED = "rate_limited"
    REDIRECT = "redirect"
    ERROR_PAGE = "error_page"
    TIMEOUT = "timeout"


@dataclass
class UIElement:
    element_type: ElementType
    selector: str
    label: str
    x: float
    y: float
    width: float
    height: float
    confidence: float
    attributes: dict = field(default_factory=dict)
    priority: int = 0

    @property
    def center(self) -> tuple[float, float]:
        return self.x + self.width / 2, self.y + self.height / 2

    @property
    def area(self) -> float:
        return self.width * self.height


@dataclass
class MousePath:
    points: list[tuple[float, float]]
    duration_ms: float
    timestamps: list[float]


@dataclass
class AgentAction:
    action_type: ActionType
    target_element: Optional[UIElement]
    value: str
    timestamp: float
    duration_ms: float
    success: bool
    result_note: str


@dataclass
class PageAnalysis:
    url: str
    title: str
    elements: list[UIElement]
    page_type: str
    has_captcha: bool
    has_mfa: bool
    has_error: bool
    error_text: str
    has_success: bool
    success_text: str
    screenshot_b64: str
    analysis_ms: float


@dataclass
class AgentSession:
    target_url: str
    session_id: str
    state: AgentState
    actions: list[AgentAction]
    page_analyses: list[PageAnalysis]
    findings: dict
    credentials_tried: list[tuple[str, str]]
    start_time: float
    end_time: float
    result: InteractionResult
    result_detail: str
    cookies: dict
    headers_captured: dict


HUMAN_REACTION_DISTRIBUTION = {
    "fast": (120, 280),
    "normal": (280, 650),
    "slow": (650, 1400),
    "reading": (1400, 3200),
}

TYPO_PATTERNS = {
    "q": ["w", "a"],
    "w": ["q", "e", "s"],
    "e": ["w", "r", "d"],
    "r": ["e", "t", "f"],
    "t": ["r", "y", "g"],
    "y": ["t", "u", "h"],
    "u": ["y", "i", "j"],
    "i": ["u", "o", "k"],
    "o": ["i", "p", "l"],
    "p": ["o", "l"],
    "a": ["q", "s", "z"],
    "s": ["a", "d", "w", "x"],
    "d": ["s", "f", "e", "c"],
    "f": ["d", "g", "r", "v"],
    "g": ["f", "h", "t", "b"],
    "h": ["g", "j", "y", "n"],
    "j": ["h", "k", "u", "m"],
    "k": ["j", "l", "i"],
    "l": ["k", "o", "p"],
    "z": ["a", "x"],
    "x": ["z", "c", "s"],
    "c": ["x", "v", "d"],
    "v": ["c", "b", "f"],
    "b": ["v", "n", "g"],
    "n": ["b", "m", "h"],
    "m": ["n", "j"],
}

PAGE_TYPE_SIGNALS = {
    "login": [
        r"(?i)(sign.?in|log.?in|login|authenticate|username|email|password)",
        r"(?i)(remember.?me|forgot.?password|create.?account)",
    ],
    "mfa": [
        r"(?i)(verification.?code|authenticator|two.?factor|2fa|otp|one.?time)",
        r"(?i)(enter.?code|verify.?identity|security.?code)",
    ],
    "captcha": [
        r"(?i)(captcha|recaptcha|hcaptcha|are.?you.?human|robot|bot.?check)",
        r"(?i)(prove.?you|not.?a.?robot|security.?check)",
    ],
    "dashboard": [
        r"(?i)(dashboard|welcome|logout|sign.?out|profile|account|settings)",
        r"(?i)(home|overview|admin|panel|control)",
    ],
    "error": [
        r"(?i)(invalid.?(credentials?|password|username|email))",
        r"(?i)(incorrect|wrong|failed|unauthorized|access.?denied|locked)",
        r"(?i)(too.?many.?attempts|rate.?limit|try.?again)",
    ],
    "rate_limit": [
        r"(?i)(too.?many|rate.?limit|slow.?down|temporarily.?blocked|wait)",
        r"(?i)(429|throttl|flood.?protect)",
    ],
}

SELECTOR_PRIORITY_MAP = {
    ElementType.INPUT_EMAIL: 10,
    ElementType.INPUT_TEXT: 8,
    ElementType.INPUT_PASSWORD: 9,
    ElementType.BUTTON_SUBMIT: 7,
    ElementType.CAPTCHA_CHECKBOX: 6,
    ElementType.MFA_INPUT: 10,
    ElementType.CHECKBOX: 3,
    ElementType.SELECT: 4,
    ElementType.BUTTON_CLICK: 2,
    ElementType.LINK: 1,
    ElementType.CAPTCHA_IMAGE: 5,
    ElementType.UNKNOWN: 0,
}

FIELD_LABEL_PATTERNS = {
    "username": ["username", "user", "login", "account", "id", "user_name", "uname"],
    "email": ["email", "e-mail", "mail", "email_address", "user_email"],
    "password": ["password", "pass", "passwd", "pwd", "secret", "passphrase"],
    "mfa": ["code", "otp", "token", "verification", "auth", "2fa", "mfa", "totp"],
    "first_name": ["first", "firstname", "first_name", "given"],
    "last_name": ["last", "lastname", "last_name", "surname", "family"],
}

SUBMIT_BUTTON_TEXTS = [
    "login", "log in", "sign in", "signin", "submit", "continue",
    "next", "enter", "authenticate", "access", "go", "proceed",
    "verify", "confirm", "send", "get started",
]

SUCCESS_INDICATORS = [
    r"(?i)(welcome|dashboard|logout|sign.?out|profile|home|account|settings|overview)",
    r"(?i)(successfully|logged.?in|authorized|access.?granted)",
]

CAPTCHA_INDICATORS = [
    r"(?i)(recaptcha|hcaptcha|turnstile|funcaptcha)",
    r"(?i)(g-recaptcha|h-captcha|cf-turnstile)",
]


def _session_id() -> str:
    return hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:10]


def _reaction_delay(profile: str = "normal") -> float:
    lo, hi = HUMAN_REACTION_DISTRIBUTION.get(profile, (280, 650))
    base = random.gauss((lo + hi) / 2, (hi - lo) / 6)
    return max(lo, min(hi, base)) / 1000.0


def _jitter_coords(x: float, y: float, radius: float = 3.0) -> tuple[float, float]:
    angle = random.uniform(0, 2 * math.pi)
    r = random.gauss(0, radius / 3)
    return x + r * math.cos(angle), y + r * math.sin(angle)


def _bezier_point(
    t: float,
    p0: tuple[float, float],
    p1: tuple[float, float],
    p2: tuple[float, float],
    p3: tuple[float, float],
) -> tuple[float, float]:
    u = 1 - t
    x = u**3 * p0[0] + 3 * u**2 * t * p1[0] + 3 * u * t**2 * p2[0] + t**3 * p3[0]
    y = u**3 * p0[1] + 3 * u**2 * t * p1[1] + 3 * u * t**2 * p2[1] + t**3 * p3[1]
    return x, y


def generate_mouse_path(
    start: tuple[float, float],
    end: tuple[float, float],
    steps: int = 0,
    speed_profile: str = "normal",
) -> MousePath:
    dist = math.hypot(end[0] - start[0], end[1] - start[1])
    if steps == 0:
        steps = max(12, int(dist / 8) + random.randint(5, 15))

    lo, hi = HUMAN_REACTION_DISTRIBUTION.get(speed_profile, (280, 650))
    total_ms = random.gauss((lo + hi) / 2, (hi - lo) / 6)
    total_ms = max(lo * 0.6, min(hi * 1.4, total_ms))

    offset_x = random.uniform(-dist * 0.3, dist * 0.3)
    offset_y = random.uniform(-dist * 0.3, dist * 0.3)
    ctrl1 = (
        start[0] + (end[0] - start[0]) * 0.3 + offset_x,
        start[1] + (end[1] - start[1]) * 0.3 + offset_y,
    )
    ctrl2 = (
        start[0] + (end[0] - start[0]) * 0.7 - offset_x * 0.5,
        start[1] + (end[1] - start[1]) * 0.7 - offset_y * 0.5,
    )

    points: list[tuple[float, float]] = []
    timestamps: list[float] = []
    t_acc = 0.0

    for i in range(steps + 1):
        t = i / steps
        ease = t * t * (3 - 2 * t)
        px, py = _bezier_point(ease, start, ctrl1, ctrl2, end)
        jx, jy = _jitter_coords(px, py, radius=2.0 if i not in (0, steps) else 0.5)
        points.append((round(jx, 2), round(jy, 2)))

        speed_variance = random.gauss(1.0, 0.15)
        t_acc += (total_ms / steps) * speed_variance
        timestamps.append(round(t_acc, 2))

    timestamps[-1] = total_ms
    return MousePath(points=points, duration_ms=total_ms, timestamps=timestamps)


def generate_typing_sequence(
    text: str,
    typo_rate: float = 0.04,
    speed_profile: str = "normal",
) -> list[tuple[str, float]]:
    lo, hi = 60, 180
    if speed_profile == "fast":
        lo, hi = 40, 100
    elif speed_profile == "slow":
        lo, hi = 100, 280

    result: list[tuple[str, float]] = []
    i = 0
    while i < len(text):
        char = text[i]
        delay = random.gauss((lo + hi) / 2, (hi - lo) / 6)
        delay = max(lo * 0.5, min(hi * 1.8, delay)) / 1000.0

        if char.lower() in TYPO_PATTERNS and random.random() < typo_rate:
            typo = random.choice(TYPO_PATTERNS[char.lower()])
            if char.isupper():
                typo = typo.upper()
            result.append((typo, delay))
            backspace_delay = random.gauss(180, 50) / 1000.0
            result.append(("\x08", max(0.08, backspace_delay)))
            result.append((char, random.gauss(120, 30) / 1000.0))
        else:
            result.append((char, delay))

        if char in ".!?," and random.random() < 0.3:
            pause = random.gauss(400, 100) / 1000.0
            result.append(("", max(0.2, pause)))

        i += 1

    return result


def _classify_input(attrs: dict) -> ElementType:
    input_type = attrs.get("type", "text").lower()
    name = attrs.get("name", "").lower()
    placeholder = attrs.get("placeholder", "").lower()
    autocomplete = attrs.get("autocomplete", "").lower()
    label_text = attrs.get("label_text", "").lower()
    combined = f"{name} {placeholder} {autocomplete} {label_text}"

    if input_type == "password":
        return ElementType.INPUT_PASSWORD
    if input_type == "email" or "email" in combined:
        return ElementType.INPUT_EMAIL
    if any(k in combined for k in FIELD_LABEL_PATTERNS["mfa"]):
        return ElementType.MFA_INPUT
    if any(k in combined for k in FIELD_LABEL_PATTERNS["username"]):
        return ElementType.INPUT_TEXT
    if input_type in ("text", ""):
        return ElementType.INPUT_TEXT
    if input_type == "checkbox":
        return ElementType.CHECKBOX
    return ElementType.UNKNOWN


def _classify_button(attrs: dict) -> ElementType:
    text = attrs.get("text", "").lower().strip()
    btn_type = attrs.get("type", "").lower()
    if btn_type == "submit":
        return ElementType.BUTTON_SUBMIT
    for t in SUBMIT_BUTTON_TEXTS:
        if t in text:
            return ElementType.BUTTON_SUBMIT
    return ElementType.BUTTON_CLICK


class DecisionEngine:
    def __init__(self, credentials: list[tuple[str, str]], max_attempts: int = 3):
        self.credentials = credentials
        self.max_attempts = max_attempts
        self._attempt_index = 0
        self._field_map: dict[str, UIElement] = {}
        self._last_analysis: Optional[PageAnalysis] = None

    def reset(self):
        self._attempt_index = 0
        self._field_map = {}
        self._last_analysis = None

    def next_credentials(self) -> Optional[tuple[str, str]]:
        if self._attempt_index >= len(self.credentials):
            return None
        cred = self.credentials[self._attempt_index]
        self._attempt_index += 1
        return cred

    def build_action_plan(self, analysis: PageAnalysis) -> list[tuple[ActionType, Optional[UIElement], str]]:
        self._last_analysis = analysis
        plan: list[tuple[ActionType, Optional[UIElement], str]] = []

        if analysis.page_type == "rate_limit":
            wait_secs = random.uniform(8.0, 20.0)
            plan.append((ActionType.WAIT, None, str(wait_secs)))
            return plan

        if analysis.page_type == "error":
            cred = self.next_credentials()
            if not cred:
                return []
            return self._fill_login_form(analysis.elements, cred[0], cred[1])

        if analysis.page_type == "login":
            cred = self.next_credentials()
            if not cred:
                return []
            return self._fill_login_form(analysis.elements, cred[0], cred[1])

        if analysis.page_type == "mfa":
            return [(ActionType.WAIT, None, "mfa_required")]

        if analysis.page_type == "captcha":
            captcha_elem = next(
                (e for e in analysis.elements if e.element_type == ElementType.CAPTCHA_CHECKBOX),
                None
            )
            if captcha_elem:
                plan.append((ActionType.HOVER, captcha_elem, ""))
                plan.append((ActionType.WAIT, None, str(random.uniform(0.4, 1.2))))
                plan.append((ActionType.CLICK, captcha_elem, ""))
            return plan

        if analysis.page_type == "dashboard":
            plan.append((ActionType.WAIT, None, str(random.uniform(0.5, 1.5))))
            return plan

        return plan

    def _fill_login_form(
        self,
        elements: list[UIElement],
        username: str,
        password: str,
    ) -> list[tuple[ActionType, Optional[UIElement], str]]:
        plan: list[tuple[ActionType, Optional[UIElement], str]] = []

        username_field = next(
            (e for e in elements if e.element_type in (ElementType.INPUT_TEXT, ElementType.INPUT_EMAIL)),
            None
        )
        password_field = next(
            (e for e in elements if e.element_type == ElementType.INPUT_PASSWORD),
            None
        )
        submit_btn = next(
            (e for e in elements if e.element_type == ElementType.BUTTON_SUBMIT),
            None
        )

        if username_field:
            plan.append((ActionType.MOVE, username_field, ""))
            plan.append((ActionType.WAIT, None, str(_reaction_delay("normal"))))
            plan.append((ActionType.CLEAR_TYPE, username_field, username))
            plan.append((ActionType.WAIT, None, str(_reaction_delay("fast"))))

        if password_field:
            plan.append((ActionType.MOVE, password_field, ""))
            plan.append((ActionType.WAIT, None, str(_reaction_delay("normal"))))
            plan.append((ActionType.CLEAR_TYPE, password_field, password))
            plan.append((ActionType.WAIT, None, str(_reaction_delay("fast"))))

        if random.random() < 0.25 and username_field and password_field:
            plan.append((ActionType.WAIT, None, str(random.uniform(0.3, 1.0))))

        if submit_btn:
            plan.append((ActionType.MOVE, submit_btn, ""))
            plan.append((ActionType.WAIT, None, str(_reaction_delay("normal"))))
            plan.append((ActionType.CLICK, submit_btn, ""))
        elif password_field:
            plan.append((ActionType.KEY_PRESS, password_field, "Enter"))

        return plan


class PageAnalyzer:
    def __init__(self):
        self._compiled_signals = {
            page_type: [re.compile(p) for p in patterns]
            for page_type, patterns in PAGE_TYPE_SIGNALS.items()
        }

    def classify_page(self, html: str, url: str) -> str:
        scores: dict[str, int] = {k: 0 for k in PAGE_TYPE_SIGNALS}
        for page_type, patterns in self._compiled_signals.items():
            for pat in patterns:
                if pat.search(html):
                    scores[page_type] += 1

        if scores.get("rate_limit", 0) > 0:
            return "rate_limit"
        if scores.get("dashboard", 0) >= 1:
            return "dashboard"
        if scores.get("captcha", 0) >= 1:
            return "captcha"
        if scores.get("mfa", 0) >= 1:
            return "mfa"
        if scores.get("error", 0) >= 1:
            return "error"
        if scores.get("login", 0) >= 1:
            return "login"
        return "unknown"

    def detect_success(self, html: str, url: str, original_url: str) -> tuple[bool, str]:
        parsed_orig = urlparse(original_url)
        parsed_curr = urlparse(url)
        if parsed_curr.path != parsed_orig.path and parsed_curr.netloc == parsed_orig.netloc:
            for pat in [re.compile(p) for p in SUCCESS_INDICATORS]:
                if pat.search(html) or pat.search(url):
                    return True, f"Redirected to {url} with success indicators"

        for pat in [re.compile(p) for p in SUCCESS_INDICATORS]:
            if pat.search(html):
                return True, f"Success indicator found: {pat.pattern[:50]}"

        return False, ""

    def detect_error(self, html: str) -> tuple[bool, str]:
        error_patterns = [re.compile(p) for p in PAGE_TYPE_SIGNALS["error"]]
        for pat in error_patterns:
            m = pat.search(html)
            if m:
                start = max(0, m.start() - 20)
                end = min(len(html), m.end() + 60)
                snippet = re.sub(r"<[^>]+>", "", html[start:end]).strip()
                return True, snippet
        return False, ""

    async def extract_elements(self, page) -> list[UIElement]:
        elements: list[UIElement] = []

        try:
            inputs = await page.query_selector_all("input:visible, input[type=hidden]")
            for inp in inputs:
                try:
                    bbox = await inp.bounding_box()
                    if not bbox:
                        continue
                    attrs = {
                        "type": await inp.get_attribute("type") or "text",
                        "name": await inp.get_attribute("name") or "",
                        "id": await inp.get_attribute("id") or "",
                        "placeholder": await inp.get_attribute("placeholder") or "",
                        "autocomplete": await inp.get_attribute("autocomplete") or "",
                        "value": await inp.get_attribute("value") or "",
                    }
                    elem_id = attrs.get("id", "")
                    label_text = ""
                    if elem_id:
                        try:
                            lbl = await page.query_selector(f'label[for="{elem_id}"]')
                            if lbl:
                                label_text = (await lbl.inner_text() or "").strip().lower()
                        except Exception:
                            pass
                    attrs["label_text"] = label_text
                    elem_type = _classify_input(attrs)
                    selector = (
                        f'input[name="{attrs["name"]}"]' if attrs["name"]
                        else f'input[id="{elem_id}"]' if elem_id
                        else f'input[type="{attrs["type"]}"]'
                    )
                    elements.append(UIElement(
                        element_type=elem_type,
                        selector=selector,
                        label=label_text or attrs["name"] or attrs["placeholder"],
                        x=bbox["x"], y=bbox["y"],
                        width=bbox["width"], height=bbox["height"],
                        confidence=0.95,
                        attributes=attrs,
                        priority=SELECTOR_PRIORITY_MAP.get(elem_type, 0),
                    ))
                except Exception:
                    continue

            buttons = await page.query_selector_all(
                "button, input[type=submit], input[type=button], [role=button]"
            )
            for btn in buttons:
                try:
                    bbox = await btn.bounding_box()
                    if not bbox or bbox["width"] < 10 or bbox["height"] < 10:
                        continue
                    text = (await btn.inner_text() or "").strip()
                    btn_type = await btn.get_attribute("type") or ""
                    attrs = {"text": text, "type": btn_type}
                    elem_type = _classify_button(attrs)
                    tag = await btn.evaluate("el => el.tagName.toLowerCase()")
                    name_attr = await btn.get_attribute("name") or ""
                    selector = (
                        f'button[type="{btn_type}"]' if tag == "button" and btn_type
                        else f'input[type="{btn_type}"]' if tag == "input"
                        else '[role=button]'
                    )
                    elements.append(UIElement(
                        element_type=elem_type,
                        selector=selector,
                        label=text[:40],
                        x=bbox["x"], y=bbox["y"],
                        width=bbox["width"], height=bbox["height"],
                        confidence=0.90,
                        attributes=attrs,
                        priority=SELECTOR_PRIORITY_MAP.get(elem_type, 0),
                    ))
                except Exception:
                    continue

            iframe_handles = await page.query_selector_all("iframe")
            for iframe in iframe_handles:
                try:
                    src = await iframe.get_attribute("src") or ""
                    bbox = await iframe.bounding_box()
                    if not bbox:
                        continue
                    is_captcha = any(
                        re.search(pat, src, re.I)
                        for pat in CAPTCHA_INDICATORS
                    )
                    if is_captcha:
                        elements.append(UIElement(
                            element_type=ElementType.CAPTCHA_IMAGE,
                            selector="iframe[src*='captcha'], iframe[src*='recaptcha']",
                            label="captcha_iframe",
                            x=bbox["x"], y=bbox["y"],
                            width=bbox["width"], height=bbox["height"],
                            confidence=0.85,
                            attributes={"src": src},
                            priority=SELECTOR_PRIORITY_MAP[ElementType.CAPTCHA_IMAGE],
                        ))
                except Exception:
                    continue

            checkbox_candidates = await page.query_selector_all(
                '.recaptcha-checkbox, [class*="captcha"] input[type=checkbox],'
                ' [id*="captcha"] input[type=checkbox], [aria-label*="robot"]'
            )
            for cb in checkbox_candidates:
                try:
                    bbox = await cb.bounding_box()
                    if not bbox:
                        continue
                    elements.append(UIElement(
                        element_type=ElementType.CAPTCHA_CHECKBOX,
                        selector=".recaptcha-checkbox",
                        label="captcha_checkbox",
                        x=bbox["x"], y=bbox["y"],
                        width=bbox["width"], height=bbox["height"],
                        confidence=0.80,
                        attributes={},
                        priority=SELECTOR_PRIORITY_MAP[ElementType.CAPTCHA_CHECKBOX],
                    ))
                except Exception:
                    continue

        except Exception:
            pass

        elements.sort(key=lambda e: (-e.priority, e.y, e.x))
        return elements


class MouseController:
    def __init__(self, page):
        self._page = page
        self._current_pos: tuple[float, float] = (0.0, 0.0)

    async def move_to(self, x: float, y: float, speed: str = "normal") -> None:
        path = generate_mouse_path(self._current_pos, (x, y), speed_profile=speed)
        for i, (px, py) in enumerate(path.points):
            await self._page.mouse.move(px, py)
            if i < len(path.points) - 1:
                interval = (path.timestamps[i + 1] - path.timestamps[i]) / 1000.0
                await asyncio.sleep(max(0.001, interval))
        self._current_pos = (x, y)

    async def click_at(self, x: float, y: float, speed: str = "normal") -> None:
        await self.move_to(x, y, speed)
        hold = random.gauss(85, 20) / 1000.0
        await self._page.mouse.down()
        await asyncio.sleep(max(0.04, hold))
        await self._page.mouse.up()
        self._current_pos = (x, y)

    async def type_text(self, element: UIElement, text: str, clear_first: bool = True) -> None:
        cx, cy = element.center
        await self.click_at(cx, cy)
        await asyncio.sleep(_reaction_delay("fast"))

        if clear_first:
            await self._page.keyboard.press("Control+a")
            await asyncio.sleep(random.uniform(0.05, 0.12))
            await self._page.keyboard.press("Delete")
            await asyncio.sleep(random.uniform(0.05, 0.15))

        seq = generate_typing_sequence(text, typo_rate=0.04)
        for char, delay in seq:
            if char == "\x08":
                await self._page.keyboard.press("Backspace")
            elif char == "":
                await asyncio.sleep(delay)
            else:
                await self._page.keyboard.type(char)
            if delay > 0:
                await asyncio.sleep(delay)

    async def scroll_to_element(self, element: UIElement) -> None:
        await self._page.evaluate(
            f'document.querySelector({json.dumps(element.selector)})?.scrollIntoView({{block:"center",behavior:"smooth"}})'
        )
        await asyncio.sleep(random.uniform(0.3, 0.7))


class AIMouseAgent:
    def __init__(
        self,
        credentials: list[tuple[str, str]],
        max_attempts: int = 5,
        headless: bool = True,
        viewport: dict = None,
        user_agent: str = None,
        capture_screenshots: bool = True,
        proxy: Optional[dict] = None,
    ):
        self.credentials = credentials
        self.max_attempts = max_attempts
        self.headless = headless
        self.viewport = viewport or {"width": 1366, "height": 768}
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        self.capture_screenshots = capture_screenshots
        self.proxy = proxy
        self._analyzer = PageAnalyzer()
        self._engine = DecisionEngine(credentials, max_attempts)
        self._session: Optional[AgentSession] = None

    async def _take_screenshot(self, page) -> str:
        if not self.capture_screenshots:
            return ""
        try:
            buf = await page.screenshot(full_page=False, type="jpeg", quality=60)
            return base64.b64encode(buf).decode()
        except Exception:
            return ""

    async def _analyze_page(self, page, original_url: str) -> PageAnalysis:
        t0 = time.monotonic()
        try:
            html = await page.content()
            url = page.url
            title = await page.title()
        except Exception:
            html, url, title = "", original_url, ""

        page_type = self._analyzer.classify_page(html, url)
        elements = await self._analyzer.extract_elements(page)
        has_captcha = page_type == "captcha" or any(
            e.element_type in (ElementType.CAPTCHA_IMAGE, ElementType.CAPTCHA_CHECKBOX)
            for e in elements
        )
        has_mfa = page_type == "mfa"
        has_error, error_text = self._analyzer.detect_error(html)
        has_success, success_text = self._analyzer.detect_success(html, url, original_url)
        screenshot_b64 = await self._take_screenshot(page)

        return PageAnalysis(
            url=url, title=title, elements=elements,
            page_type=page_type,
            has_captcha=has_captcha, has_mfa=has_mfa,
            has_error=has_error, error_text=error_text,
            has_success=has_success, success_text=success_text,
            screenshot_b64=screenshot_b64,
            analysis_ms=(time.monotonic() - t0) * 1000,
        )

    async def _execute_action(
        self,
        page,
        mouse: MouseController,
        action_type: ActionType,
        element: Optional[UIElement],
        value: str,
    ) -> AgentAction:
        t0 = time.monotonic()
        success = True
        result_note = ""

        try:
            if action_type == ActionType.WAIT:
                secs = float(value) if value not in ("mfa_required",) else 0
                if value == "mfa_required":
                    result_note = "mfa_required"
                else:
                    await asyncio.sleep(secs)

            elif action_type == ActionType.NAVIGATE:
                await page.goto(value, wait_until="domcontentloaded", timeout=20000)
                await asyncio.sleep(random.uniform(0.5, 1.2))

            elif action_type == ActionType.SCREENSHOT:
                result_note = await self._take_screenshot(page)

            elif action_type == ActionType.MOVE and element:
                cx, cy = _jitter_coords(*element.center, radius=4.0)
                await mouse.move_to(cx, cy)

            elif action_type == ActionType.CLICK and element:
                cx, cy = _jitter_coords(*element.center, radius=3.0)
                await mouse.click_at(cx, cy)
                await asyncio.sleep(_reaction_delay("fast"))

            elif action_type == ActionType.HOVER and element:
                cx, cy = _jitter_coords(*element.center, radius=5.0)
                await mouse.move_to(cx, cy, speed="slow")
                await asyncio.sleep(random.uniform(0.3, 0.8))

            elif action_type in (ActionType.TYPE, ActionType.CLEAR_TYPE) and element:
                await mouse.scroll_to_element(element)
                await asyncio.sleep(random.uniform(0.1, 0.3))
                clear = action_type == ActionType.CLEAR_TYPE
                await mouse.type_text(element, value, clear_first=clear)

            elif action_type == ActionType.KEY_PRESS and element:
                await page.keyboard.press(value)
                await asyncio.sleep(_reaction_delay("fast"))

            elif action_type == ActionType.SCROLL:
                await page.mouse.wheel(0, int(value))
                await asyncio.sleep(random.uniform(0.2, 0.5))

        except Exception as e:
            success = False
            result_note = str(e)[:200]

        return AgentAction(
            action_type=action_type,
            target_element=element,
            value=value[:100] if value else "",
            timestamp=t0,
            duration_ms=(time.monotonic() - t0) * 1000,
            success=success,
            result_note=result_note,
        )

    async def run(self, target_url: str) -> AgentSession:
        from playwright.async_api import async_playwright

        session = AgentSession(
            target_url=target_url,
            session_id=_session_id(),
            state=AgentState.IDLE,
            actions=[],
            page_analyses=[],
            findings={},
            credentials_tried=[],
            start_time=time.time(),
            end_time=0.0,
            result=InteractionResult.FAILED,
            result_detail="",
            cookies={},
            headers_captured={},
        )
        self._session = session
        self._engine.reset()

        launch_kwargs: dict = {
            "headless": self.headless,
            "args": [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--disable-infobars",
                "--window-size=1366,768",
                "--lang=en-US",
            ],
        }
        if self.proxy:
            launch_kwargs["proxy"] = self.proxy

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**launch_kwargs)
            context = await browser.new_context(
                viewport=self.viewport,
                user_agent=self.user_agent,
                locale="en-US",
                timezone_id="America/New_York",
                java_script_enabled=True,
                ignore_https_errors=True,
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                },
            )

            await context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
                window.chrome = {runtime: {}};
                Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (params) =>
                    params.name === 'notifications'
                        ? Promise.resolve({state: Notification.permission})
                        : originalQuery(params);
            """)

            page = await context.new_page()
            mouse = MouseController(page)

            try:
                session.state = AgentState.NAVIGATING
                await page.goto(target_url, wait_until="domcontentloaded", timeout=25000)
                await asyncio.sleep(random.uniform(0.8, 1.8))

                for attempt_num in range(self.max_attempts + 2):
                    if session.state in (AgentState.COMPLETE, AgentState.FAILED):
                        break

                    session.state = AgentState.ANALYZING
                    analysis = await self._analyze_page(page, target_url)
                    session.page_analyses.append(analysis)

                    if analysis.has_success:
                        session.state = AgentState.COMPLETE
                        session.result = InteractionResult.SUCCESS
                        session.result_detail = analysis.success_text
                        try:
                            raw_cookies = await context.cookies()
                            session.cookies = {c["name"]: c["value"] for c in raw_cookies}
                        except Exception:
                            pass
                        break

                    if analysis.has_mfa:
                        session.result = InteractionResult.MFA_REQUIRED
                        session.result_detail = "MFA prompt detected, manual intervention required"
                        session.state = AgentState.FAILED
                        break

                    if analysis.page_type == "rate_limit":
                        session.result = InteractionResult.RATE_LIMITED
                        session.result_detail = "Rate limiting detected"
                        wait_action = await self._execute_action(
                            page, mouse, ActionType.WAIT, None,
                            str(random.uniform(10.0, 25.0))
                        )
                        session.actions.append(wait_action)
                        continue

                    action_plan = self._engine.build_action_plan(analysis)
                    if not action_plan:
                        session.state = AgentState.FAILED
                        session.result_detail = "No actionable plan generated — credentials exhausted or unknown page"
                        break

                    session.state = AgentState.INTERACTING
                    for action_type, element, value in action_plan:
                        if value == "mfa_required":
                            session.result = InteractionResult.MFA_REQUIRED
                            session.state = AgentState.FAILED
                            break
                        action = await self._execute_action(page, mouse, action_type, element, value)
                        session.actions.append(action)
                        if not action.success:
                            continue

                    if session.state == AgentState.FAILED:
                        break

                    await page.wait_for_load_state("domcontentloaded", timeout=10000)
                    await asyncio.sleep(random.uniform(0.6, 1.4))

                    if attempt_num == self.max_attempts - 1:
                        session.result = InteractionResult.FAILED
                        session.result_detail = f"Max attempts ({self.max_attempts}) reached without success"
                        session.state = AgentState.FAILED

            except Exception as e:
                session.result = InteractionResult.FAILED
                session.result_detail = f"Agent exception: {str(e)[:300]}"
                session.state = AgentState.FAILED
            finally:
                try:
                    raw_cookies = await context.cookies()
                    session.cookies = {c["name"]: c["value"] for c in raw_cookies}
                except Exception:
                    pass
                await browser.close()

        session.end_time = time.time()
        session.findings = _build_findings(session)
        return session

    def run_sync(self, target_url: str) -> AgentSession:
        return asyncio.run(self.run(target_url))


def _build_findings(session: AgentSession) -> dict:
    total_pages = len(session.page_analyses)
    page_types_seen = list({a.page_type for a in session.page_analyses})
    elements_found: dict[str, int] = {}
    for analysis in session.page_analyses:
        for elem in analysis.elements:
            key = elem.element_type.value
            elements_found[key] = elements_found.get(key, 0) + 1

    return {
        "result": session.result.value,
        "result_detail": session.result_detail,
        "total_actions": len(session.actions),
        "total_pages_analyzed": total_pages,
        "page_types_encountered": page_types_seen,
        "elements_discovered": elements_found,
        "cookies_captured": list(session.cookies.keys()),
        "captcha_encountered": any(a.has_captcha for a in session.page_analyses),
        "mfa_encountered": any(a.has_mfa for a in session.page_analyses),
        "credentials_tried": len(session.credentials_tried),
        "duration_seconds": round(session.end_time - session.start_time, 2),
        "session_id": session.session_id,
    }


def serialize_session(session: AgentSession) -> dict:
    def action_to_dict(a: AgentAction) -> dict:
        return {
            "action": a.action_type.value,
            "element_type": a.target_element.element_type.value if a.target_element else None,
            "element_label": a.target_element.label if a.target_element else None,
            "value_preview": a.value[:30] + "..." if len(a.value) > 30 else a.value,
            "duration_ms": round(a.duration_ms, 2),
            "success": a.success,
            "note": a.result_note[:100] if a.result_note else "",
        }

    def analysis_to_dict(a: PageAnalysis) -> dict:
        return {
            "url": a.url,
            "title": a.title,
            "page_type": a.page_type,
            "has_captcha": a.has_captcha,
            "has_mfa": a.has_mfa,
            "has_error": a.has_error,
            "error_text": a.error_text[:200] if a.error_text else "",
            "has_success": a.has_success,
            "success_text": a.success_text[:200] if a.success_text else "",
            "elements_count": len(a.elements),
            "elements": [
                {
                    "type": e.element_type.value,
                    "label": e.label,
                    "selector": e.selector,
                    "confidence": e.confidence,
                }
                for e in a.elements[:20]
            ],
            "analysis_ms": round(a.analysis_ms, 2),
            "has_screenshot": bool(a.screenshot_b64),
        }

    return {
        "session_id": session.session_id,
        "target_url": session.target_url,
        "state": session.state.value,
        "result": session.result.value,
        "result_detail": session.result_detail,
        "start_time": session.start_time,
        "end_time": session.end_time,
        "duration_seconds": round(session.end_time - session.start_time, 2),
        "findings": session.findings,
        "cookies": session.cookies,
        "actions": [action_to_dict(a) for a in session.actions],
        "page_analyses": [analysis_to_dict(a) for a in session.page_analyses],
    }


def run_ai_mouse_agent(
    target_url: str,
    credentials: list[tuple[str, str]] = None,
    max_attempts: int = 5,
    headless: bool = True,
    capture_screenshots: bool = True,
    proxy: Optional[dict] = None,
) -> dict:
    if not credentials:
        credentials = [("admin", "admin"), ("admin", "password"), ("admin", "123456")]
    agent = AIMouseAgent(
        credentials=credentials,
        max_attempts=max_attempts,
        headless=headless,
        capture_screenshots=capture_screenshots,
        proxy=proxy,
    )
    session = agent.run_sync(target_url)
    return serialize_session(session)