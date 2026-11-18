"""Password Strength Analyzer & Generator with cybersecurity-focused checks."""

import math
import secrets
import string
import tkinter as tk

# Common breached/weak passwords (stored lowercase for case-insensitive matching)
COMMON_PASSWORDS = {
    "123456", "12345678", "123456789", "1234567890", "password", "password1",
    "password123", "password1!", "qwerty", "qwerty123", "abc123", "111111",
    "123123", "admin", "admin123", "admin@123", "letmein", "welcome",
    "monkey", "dragon", "iloveyou", "sunshine", "princess", "football",
    "baseball", "superman", "trustno1", "passw0rd", "p@ssword", "p@ssw0rd",
    "changeme", "root", "toor", "guest", "default", "master", "login",
}

KEYBOARD_WALKS = (
    "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn", "qazwsx",
    "1qaz2wsx", "1q2w3e4r", "!qaz@wsx", "poiuyt", "lkjhgf", "mnbvcx",
)

SPECIAL_CHARS = set(string.punctuation)


def has_repeated_chars(password: str, run_length: int = 3) -> bool:
    """Return True if the password contains `run_length` or more identical consecutive chars."""
    if len(password) < run_length:
        return False
    count = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            count += 1
            if count >= run_length:
                return True
        else:
            count = 1
    return False


def has_sequence(password: str, seq_length: int = 4) -> bool:
    """Return True if the password contains ascending/descending alphanumeric sequences."""
    if len(password) < seq_length:
        return False
    lowered = password.lower()
    run = 1
    prev_diff = None
    for i in range(1, len(lowered)):
        if lowered[i].isalnum() and lowered[i - 1].isalnum():
            diff = ord(lowered[i]) - ord(lowered[i - 1])
            if diff in (1, -1) and (prev_diff is None or diff == prev_diff):
                run += 1
                prev_diff = diff
                if run >= seq_length:
                    return True
            else:
                run = 2 if diff in (1, -1) else 1
                prev_diff = diff if diff in (1, -1) else None
        else:
            run = 1
            prev_diff = None
    return False


def has_keyboard_walk(password: str) -> bool:
    """Return True if the password contains a common keyboard walk pattern."""
    lowered = password.lower()
    return any(walk in lowered or walk[::-1] in lowered for walk in KEYBOARD_WALKS)


def calculate_entropy(password: str) -> float:
    """Estimate effective password entropy in bits, accounting for character diversity."""
    if not password:
        return 0.0

    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in SPECIAL_CHARS for c in password):
        pool += len(SPECIAL_CHARS)
    if any(c.isspace() for c in password):
        pool += 1

    if pool == 0:
        pool = 26

    # Pool-based entropy
    pool_entropy = len(password) * math.log2(pool)

    # Penalize low character uniqueness (e.g., "Aaaaaaaa1!")
    unique_ratio = len(set(password)) / len(password)
    effective_entropy = pool_entropy * (0.5 + 0.5 * unique_ratio)
    return round(effective_entropy, 1)


def estimate_crack_time(entropy_bits: float) -> str:
    """Estimate offline brute-force crack time assuming 10^10 guesses/sec (GPU rig)."""
    if entropy_bits <= 0:
        return "Instant"

    guesses_per_sec = 1e10
    # Average crack time is half the keyspace: 2^(entropy - 1)
    seconds = (2 ** max(entropy_bits - 1, 0)) / guesses_per_sec

    if seconds < 1:
        return "Instant"
    if seconds < 60:
        return f"{int(seconds)} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{int(hours)} hours"
    days = hours / 24
    if days < 365:
        return f"{int(days)} days"
    years = days / 365.25
    if years < 1_000:
        return f"{int(years)} years"
    if years < 1_000_000:
        return f"{years / 1_000:.1f}k years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f}M years"
    return "Centuries+"


def analyze_password(password: str, custom_words: list[str] | None = None) -> dict:
    """Analyze password strength and return score, rating, metrics, criteria, and feedback."""
    if not password:
        return {
            "score": 0,
            "rating": "Enter a password",
            "color": "#9ca3af",
            "entropy": 0.0,
            "crack_time": "—",
            "criteria": {
                "min_length": False,
                "recommended_length": False,
                "has_upper": False,
                "has_lower": False,
                "has_digit": False,
                "has_special": False,
            },
            "feedback": ["Type or generate a password to analyze its security."],
        }

    length = len(password)
    criteria = {
        "min_length": length >= 8,
        "recommended_length": length >= 12,
        "has_upper": any(c.isupper() for c in password),
        "has_lower": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_special": any(c in SPECIAL_CHARS for c in password),
    }

    feedback = []
    score = 0

    # Length scoring (tiered)
    if length >= 8:
        score += 15
    else:
        feedback.append("Use at least 8 characters (12+ recommended).")

    if length >= 12:
        score += 15
    elif length >= 8:
        feedback.append("Increase length to 12+ characters for stronger resistance.")

    if length >= 16:
        score += 10

    # Character class scoring
    if criteria["has_upper"]:
        score += 15
    else:
        feedback.append("Add uppercase letters (A-Z).")

    if criteria["has_lower"]:
        score += 15
    else:
        feedback.append("Add lowercase letters (a-z).")

    if criteria["has_digit"]:
        score += 15
    else:
        feedback.append("Add numbers (0-9).")

    if criteria["has_special"]:
        score += 15
    else:
        feedback.append("Add special symbols (e.g., !@#$%^&*).")

    # Security pattern penalties
    lowered = password.lower().strip()
    is_common = lowered in COMMON_PASSWORDS
    if is_common:
        score = min(score, 15)
        feedback.insert(0, "This is a commonly breached password. Avoid it completely.")

    if password != password.strip():
        score -= 10
        feedback.append("Avoid leading or trailing spaces.")

    if has_repeated_chars(password):
        score -= 15
        feedback.append("Avoid repeated characters (e.g., 'aaa' or '111').")

    if has_sequence(password):
        score -= 15
        feedback.append("Avoid sequential characters (e.g., '1234' or 'abcd').")

    if has_keyboard_walk(password):
        score -= 15
        feedback.append("Avoid predictable keyboard patterns (e.g., 'qwerty').")

    if custom_words:
        cleaned_words = [w.strip().lower() for w in custom_words if len(w.strip()) >= 3]
        if any(word in lowered for word in cleaned_words):
            score -= 20
            feedback.insert(0, "Contains your personal word verbatim — vulnerable to OSINT/targeted attacks.")

    score = max(0, min(100, score))
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    if score < 30:
        rating, color = "Very Weak ❌", "#ef4444"
    elif score < 55:
        rating, color = "Weak ⚠️", "#f97316"
    elif score < 75:
        rating, color = "Moderate ⚠️", "#eab308"
    elif score < 90:
        rating, color = "Strong ✅", "#22c55e"
    else:
        rating, color = "Very Strong 🛡️", "#10b981"

    if not feedback:
        feedback.append("Excellent! Strong length, diversity, and no predictable patterns.")

    return {
        "score": score,
        "rating": rating,
        "color": color,
        "entropy": entropy,
        "crack_time": crack_time,
        "criteria": criteria,
        "feedback": feedback,
    }


def generate_strong_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password using `secrets`."""
    if length < 12:
        length = 12

    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    pools = [
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        symbols,
    ]
    all_chars = "".join(pools)

    # Guarantee at least one character from each category
    chars = [secrets.choice(pool) for pool in pools]
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(pools)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


PASSPHRASE_WORDS = [
    "amber", "anchor", "atlas", "badge", "bamboo", "beacon", "bison", "blaze",
    "breeze", "bridge", "cactus", "canyon", "cedar", "cipher", "cloud", "cobalt",
    "comet", "compass", "copper", "coral", "cosmic", "crimson", "crystal", "delta",
    "desert", "dragon", "echo", "ember", "falcon", "fjord", "flame", "forest",
    "frost", "galaxy", "glacier", "granite", "harbor", "hawk", "horizon", "island",
    "jasper", "jungle", "kestrel", "lantern", "lemon", "lotus", "lunar", "mango",
    "marble", "meadow", "meteor", "mirage", "monarch", "nebula", "nectar", "oak",
    "oasis", "ocean", "onyx", "orbit", "orchid", "otter", "panther", "pebble",
    "phoenix", "pine", "planet", "prism", "quartz", "raven", "ridge", "river",
    "rocket", "saffron", "sapphire", "shadow", "shield", "silver", "solstice",
    "spark", "summit", "thunder", "tiger", "timber", "topaz", "tundra", "valley",
    "velvet", "vertex", "voyage", "willow", "zenith", "zephyr",
]


def generate_passphrase(num_words: int = 4) -> str:
    """Generate a memorable multi-word passphrase with random separator and digits."""
    if num_words < 3:
        num_words = 3
    rng = secrets.SystemRandom()
    words = [word.capitalize() for word in rng.sample(PASSPHRASE_WORDS, num_words)]
    sep = secrets.choice("-_!@#$")
    suffix_num = secrets.randbelow(90) + 10
    suffix_sym = secrets.choice("!@#$%^&*")
    return f"{sep.join(words)}{sep}{suffix_num}{suffix_sym}"


def generate_from_custom_words(word1: str, word2: str = "") -> str:
    """Transform custom words into a salted, randomized password using `secrets`."""
    raw_words = [w.strip() for w in (word1, word2) if w.strip()]
    if not raw_words:
        return generate_strong_password(16)

    leet_map = {"a": "@", "e": "3", "i": "!", "o": "0", "s": "$", "t": "7"}
    symbols = "!@#$%^&*-_=+"
    rng = secrets.SystemRandom()

    transformed_parts = []
    for word in raw_words:
        # Use only a short fragment (up to 3 chars) so full personal info is not exposed
        fragment = word[:3]
        chars = []
        for ch in fragment:
            lower = ch.lower()
            if lower in leet_map and secrets.randbelow(2) == 0:
                chars.append(leet_map[lower])
            elif ch.isalpha():
                chars.append(ch.upper() if secrets.randbelow(2) == 0 else ch.lower())
            else:
                chars.append(ch)
        transformed_parts.append("".join(chars))

    # Inject cryptographic salt (random chars, digits, symbols) around and between fragments
    salt_pool = string.ascii_letters + string.digits + symbols
    segments = [
        "".join(secrets.choice(salt_pool) for _ in range(3)),
        secrets.choice(symbols) + str(secrets.randbelow(90) + 10),
    ]
    for part in transformed_parts:
        segments.append(part)
        segments.append("".join(secrets.choice(salt_pool) for _ in range(3)))

    rng.shuffle(segments)
    candidate = "".join(segments)

    # Guarantee all 4 character classes are present
    checks_and_pools = [
        (any(c.isupper() for c in candidate), string.ascii_uppercase),
        (any(c.islower() for c in candidate), string.ascii_lowercase),
        (any(c.isdigit() for c in candidate), string.digits),
        (any(c in SPECIAL_CHARS for c in candidate), symbols),
    ]
    extra = [secrets.choice(pool) for present, pool in checks_and_pools if not present]
    if extra:
        candidate_list = list(candidate) + extra
        rng.shuffle(candidate_list)
        candidate = "".join(candidate_list)

    return candidate


class PasswordCheckerApp:
    """Tkinter GUI for the Cybersecurity Password Strength Analyzer."""

    BG_WINDOW = "#12121f"
    BG_CARD = "#1e1e32"
    BG_INPUT = "#2a2a42"
    FG_TEXT = "#f3f4f6"
    FG_MUTED = "#9ca3af"

    CRITERIA_LABELS = [
        ("min_length", "At least 8 characters"),
        ("recommended_length", "12+ characters (recommended)"),
        ("has_upper", "Uppercase letter (A-Z)"),
        ("has_lower", "Lowercase letter (a-z)"),
        ("has_digit", "Number (0-9)"),
        ("has_special", "Special symbol (!@#$...)"),
    ]

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Cybersecurity Password Strength Analyzer")
        self.root.geometry("640x760")
        self.root.minsize(560, 720)
        self.root.config(bg=self.BG_WINDOW)

        self.show_password = tk.BooleanVar(value=False)
        self.criteria_widgets: dict[str, tk.Label] = {}

        self._build_ui()
        self.update_analysis()

    def _build_ui(self) -> None:
        card = tk.Frame(self.root, bg=self.BG_CARD, padx=36, pady=28)
        card.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(
            card,
            text="🔐 Password Strength Analyzer",
            font=("Segoe UI", 18, "bold"),
            fg=self.FG_TEXT,
            bg=self.BG_CARD,
        ).pack(pady=(0, 4))

        tk.Label(
            card,
            text="Live entropy, pattern & brute-force resistance check",
            font=("Segoe UI", 10),
            fg=self.FG_MUTED,
            bg=self.BG_CARD,
        ).pack(pady=(0, 18))

        # Input row
        input_frame = tk.Frame(card, bg=self.BG_CARD)
        input_frame.pack(fill="x", pady=(0, 12))

        self.entry = tk.Entry(
            input_frame,
            show="*",
            width=30,
            font=("Segoe UI", 12),
            bg=self.BG_INPUT,
            fg=self.FG_TEXT,
            insertbackground=self.FG_TEXT,
            relief="flat",
            bd=6,
        )
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<KeyRelease>", lambda _e: self.update_analysis())
        self.entry.bind("<Return>", lambda _e: self.update_analysis())
        self.entry.bind("<<Paste>>", lambda _e: self.root.after_idle(self.update_analysis))
        self.entry.bind("<<Cut>>", lambda _e: self.root.after_idle(self.update_analysis))
        self.entry.focus_set()

        self.eye_button = tk.Button(
            input_frame,
            text="👁",
            command=self.toggle_password,
            font=("Segoe UI", 11),
            bg="#374151",
            fg=self.FG_TEXT,
            activebackground="#4b5563",
            activeforeground=self.FG_TEXT,
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=4,
        )
        self.eye_button.pack(side="left", padx=(8, 0))

        # Action buttons row
        btn_frame = tk.Frame(card, bg=self.BG_CARD)
        btn_frame.pack(fill="x", pady=(0, 16))

        tk.Button(
            btn_frame,
            text="Generate Strong",
            command=self.fill_generated_password,
            font=("Segoe UI", 10, "bold"),
            bg="#059669",
            fg="white",
            activebackground="#047857",
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            btn_frame,
            text="4-Word Passphrase",
            command=self.fill_passphrase,
            font=("Segoe UI", 10, "bold"),
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            btn_frame,
            text="Clear",
            command=self.clear_input,
            font=("Segoe UI", 10),
            bg="#374151",
            fg=self.FG_TEXT,
            activebackground="#4b5563",
            activeforeground=self.FG_TEXT,
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        ).pack(side="left")

        # Strength progress bar
        self.bar_width = 430
        self.bar_canvas = tk.Canvas(
            card,
            width=self.bar_width,
            height=12,
            bg="#2d2d44",
            highlightthickness=0,
        )
        self.bar_canvas.pack(pady=(0, 10))
        self.bar_fill = self.bar_canvas.create_rectangle(0, 0, 0, 12, fill="#9ca3af", width=0)

        # Result & metrics
        self.result_label = tk.Label(
            card,
            text="",
            font=("Segoe UI", 14, "bold"),
            bg=self.BG_CARD,
        )
        self.result_label.pack(pady=(2, 4))

        self.metrics_label = tk.Label(
            card,
            text="",
            font=("Segoe UI", 10),
            fg=self.FG_MUTED,
            bg=self.BG_CARD,
        )
        self.metrics_label.pack(pady=(0, 14))

        # Criteria checklist
        checklist_frame = tk.LabelFrame(
            card,
            text=" Security Criteria ",
            font=("Segoe UI", 10, "bold"),
            fg=self.FG_TEXT,
            bg=self.BG_CARD,
            bd=1,
            relief="groove",
            padx=14,
            pady=10,
        )
        checklist_frame.pack(fill="x", pady=(0, 12))

        for key, label_text in self.CRITERIA_LABELS:
            lbl = tk.Label(
                checklist_frame,
                text=f"✖  {label_text}",
                font=("Segoe UI", 10),
                fg="#ef4444",
                bg=self.BG_CARD,
                anchor="w",
            )
            lbl.pack(fill="x", pady=1)
            self.criteria_widgets[key] = lbl

        # Actionable feedback
        self.feedback_label = tk.Label(
            card,
            text="",
            font=("Segoe UI", 9),
            fg="#fbbf24",
            bg=self.BG_CARD,
            justify="left",
            wraplength=430,
            anchor="w",
        )
        self.feedback_label.pack(fill="x", pady=(0, 12))

        # Custom seed generator section
        custom_frame = tk.LabelFrame(
            card,
            text=" Custom Seed Generator (Optional) ",
            font=("Segoe UI", 10, "bold"),
            fg=self.FG_TEXT,
            bg=self.BG_CARD,
            bd=1,
            relief="groove",
            padx=14,
            pady=10,
        )
        custom_frame.pack(fill="x")

        words_row = tk.Frame(custom_frame, bg=self.BG_CARD)
        words_row.pack(fill="x", pady=(0, 8))

        tk.Label(
            words_row, text="Word 1:", font=("Segoe UI", 9), fg=self.FG_MUTED, bg=self.BG_CARD
        ).pack(side="left")
        self.word1_entry = tk.Entry(
            words_row,
            width=14,
            font=("Segoe UI", 10),
            bg=self.BG_INPUT,
            fg=self.FG_TEXT,
            insertbackground=self.FG_TEXT,
            relief="flat",
            bd=4,
        )
        self.word1_entry.pack(side="left", padx=(4, 12))

        tk.Label(
            words_row, text="Word 2:", font=("Segoe UI", 9), fg=self.FG_MUTED, bg=self.BG_CARD
        ).pack(side="left")
        self.word2_entry = tk.Entry(
            words_row,
            width=14,
            font=("Segoe UI", 10),
            bg=self.BG_INPUT,
            fg=self.FG_TEXT,
            insertbackground=self.FG_TEXT,
            relief="flat",
            bd=4,
        )
        self.word2_entry.pack(side="left", padx=(4, 0))

        custom_btn_row = tk.Frame(custom_frame, bg=self.BG_CARD)
        custom_btn_row.pack(fill="x")

        tk.Button(
            custom_btn_row,
            text="Generate from Words",
            command=self.fill_custom_password,
            font=("Segoe UI", 9, "bold"),
            bg="#7c3aed",
            fg="white",
            activebackground="#6d28d9",
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=4,
        ).pack(side="left")

        tk.Label(
            custom_btn_row,
            text="Salted with CSPRNG; avoid personal names for critical accounts.",
            font=("Segoe UI", 8),
            fg=self.FG_MUTED,
            bg=self.BG_CARD,
        ).pack(side="left", padx=(10, 0))

    def toggle_password(self) -> None:
        """Toggle password visibility between masked and plain text."""
        visible = not self.show_password.get()
        self.show_password.set(visible)
        self.entry.config(show="" if visible else "*")
        self.eye_button.config(text="🙈" if visible else "👁")

    def _set_generated_password(self, pwd: str) -> None:
        """Insert a generated password, reveal it, and refresh analysis."""
        self.entry.delete(0, tk.END)
        self.entry.insert(0, pwd)
        if not self.show_password.get():
            self.toggle_password()
        self.update_analysis()

    def fill_generated_password(self) -> None:
        """Generate a secure random password and display it in the input box."""
        self._set_generated_password(generate_strong_password(16))

    def fill_passphrase(self) -> None:
        """Generate a memorable 4-word passphrase and display it."""
        self._set_generated_password(generate_passphrase(4))

    def fill_custom_password(self) -> None:
        """Generate a salted, randomized password from optional custom words."""
        pwd = generate_from_custom_words(self.word1_entry.get(), self.word2_entry.get())
        self._set_generated_password(pwd)

    def clear_input(self) -> None:
        """Clear the password input and reset analysis."""
        self.entry.delete(0, tk.END)
        self.update_analysis()

    def update_analysis(self) -> None:
        """Run password analysis and refresh all UI elements."""
        custom_words = [self.word1_entry.get(), self.word2_entry.get()]
        result = analyze_password(self.entry.get(), custom_words=custom_words)

        self.result_label.config(text=result["rating"], fg=result["color"])
        self.metrics_label.config(
            text=f"Score: {result['score']}/100  |  Entropy: {result['entropy']} bits  |  Crack Time: {result['crack_time']}"
        )

        fill_w = int(self.bar_width * (result["score"] / 100))
        self.bar_canvas.coords(self.bar_fill, 0, 0, fill_w, 12)
        self.bar_canvas.itemconfig(self.bar_fill, fill=result["color"])

        for key, label_text in self.CRITERIA_LABELS:
            passed = result["criteria"][key]
            self.criteria_widgets[key].config(
                text=f"{'✔' if passed else '✖'}  {label_text}",
                fg="#22c55e" if passed else "#ef4444",
            )

        feedback_text = "\n".join(f"• {msg}" for msg in result["feedback"][:4])
        is_all_good = result["score"] >= 90 and len(result["feedback"]) == 1
        self.feedback_label.config(
            text=feedback_text,
            fg="#10b981" if is_all_good else "#fbbf24",
        )


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()
