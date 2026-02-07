#!/usr/bin/env python3
"""
Purple Team Platform - Human-Like Behavior Simulation
Simulate realistic human activity patterns to:
1. Avoid triggering rate limits and IDS during assessments
2. Test detection of "low and slow" attacks
3. Validate behavioral detection capabilities

Systems Thinking: Counter-intuitive - attackers act like humans to evade detection.
"""

import random
import time
from datetime import datetime, timedelta
from typing import Optional, Callable, List
import math

try:
    from .tui import tui, C
except ImportError:
    from tui import tui, C


class HumanBehavior:
    """Simulate human-like behavior patterns."""

    # Working hours (default 9-5 with some flex)
    WORK_START = 8
    WORK_END = 18

    # User agent strings (realistic)
    USER_AGENTS = [
        # Chrome on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        # Firefox on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        # Edge on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        # Chrome on Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Safari on Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # Chrome on Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Firefox on Linux
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]

    def __init__(self, profile: str = "normal"):
        """Initialize with a behavior profile.

        Profiles:
        - stealth: Very slow, maximum randomization (for testing detection)
        - normal: Balanced speed and stealth (default)
        - fast: Faster but still human-like
        - aggressive: Minimal delays (for when speed matters)
        """
        self.profile = profile
        self.session_start = datetime.now()
        self.action_count = 0
        self.last_action = None
        self._user_agent = None
        self._session_id = self._generate_session_id()

        # Profile settings
        self.profiles = {
            'stealth': {
                'base_delay': 5.0,
                'jitter_factor': 0.8,
                'burst_probability': 0.1,
                'break_probability': 0.15,
                'break_duration_range': (30, 180),
                'requests_per_burst': (1, 3),
                'working_hours_only': True,
            },
            'normal': {
                'base_delay': 2.0,
                'jitter_factor': 0.5,
                'burst_probability': 0.3,
                'break_probability': 0.05,
                'break_duration_range': (10, 60),
                'requests_per_burst': (2, 5),
                'working_hours_only': False,
            },
            'fast': {
                'base_delay': 0.5,
                'jitter_factor': 0.3,
                'burst_probability': 0.5,
                'break_probability': 0.02,
                'break_duration_range': (5, 20),
                'requests_per_burst': (3, 8),
                'working_hours_only': False,
            },
            'aggressive': {
                'base_delay': 0.1,
                'jitter_factor': 0.2,
                'burst_probability': 0.8,
                'break_probability': 0.01,
                'break_duration_range': (1, 5),
                'requests_per_burst': (5, 15),
                'working_hours_only': False,
            },
        }

        self.settings = self.profiles.get(profile, self.profiles['normal'])

    def _generate_session_id(self) -> str:
        """Generate a realistic session ID."""
        chars = 'abcdef0123456789'
        return ''.join(random.choice(chars) for _ in range(32))

    def get_user_agent(self, rotate: bool = False) -> str:
        """Get a user agent string.

        Args:
            rotate: If True, pick a new random UA. If False, keep consistent.
        """
        if rotate or self._user_agent is None:
            self._user_agent = random.choice(self.USER_AGENTS)
        return self._user_agent

    def get_session_headers(self) -> dict:
        """Get realistic browser headers."""
        return {
            'User-Agent': self.get_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }

    def is_working_hours(self) -> bool:
        """Check if current time is within working hours."""
        now = datetime.now()
        # Weekday (0 = Monday, 6 = Sunday)
        if now.weekday() >= 5:  # Weekend
            return False
        return self.WORK_START <= now.hour < self.WORK_END

    def calculate_delay(self) -> float:
        """Calculate a human-like delay.

        Uses a combination of:
        - Base delay from profile
        - Random jitter (gaussian distribution)
        - Occasional longer pauses (simulating thinking/distractions)
        """
        base = self.settings['base_delay']
        jitter = self.settings['jitter_factor']

        # Gaussian jitter for natural variation
        delay = random.gauss(base, base * jitter)

        # Ensure non-negative
        delay = max(0.1, delay)

        # Occasional longer pause (simulating reading, thinking)
        if random.random() < self.settings['break_probability']:
            min_break, max_break = self.settings['break_duration_range']
            delay += random.uniform(min_break, max_break)

        # Simulate fatigue - slightly longer delays over time
        session_minutes = (datetime.now() - self.session_start).seconds / 60
        fatigue_factor = 1 + (session_minutes / 120) * 0.2  # +20% after 2 hours
        delay *= min(fatigue_factor, 1.5)  # Cap at 50% increase

        return delay

    def wait(self, reason: str = None, show: bool = True):
        """Wait with human-like timing.

        Args:
            reason: Optional reason for the wait (for logging)
            show: Whether to show countdown
        """
        delay = self.calculate_delay()

        if show and delay > 1:
            # Show countdown for longer waits
            remaining = delay
            while remaining > 0:
                msg = f"Waiting {remaining:.1f}s"
                if reason:
                    msg += f" ({reason})"
                tui.spinner(msg)
                time.sleep(0.1)
                remaining -= 0.1
            print()  # Clear spinner line
        else:
            time.sleep(delay)

        self.action_count += 1
        self.last_action = datetime.now()

    def typing_delay(self, text: str) -> float:
        """Calculate realistic typing delay for text length.

        Average typing speed: 40-60 WPM = 200-300 CPM
        """
        chars = len(text)
        # Random typing speed (characters per minute)
        cpm = random.gauss(250, 50)
        base_time = (chars / cpm) * 60

        # Add thinking pauses
        pauses = text.count(' ') * random.uniform(0.1, 0.3)

        return base_time + pauses

    def simulate_typing(self, text: str, show: bool = True):
        """Simulate typing text with realistic timing."""
        delay = self.typing_delay(text)
        if show:
            tui.spinner(f"Typing {len(text)} characters...")
        time.sleep(delay)
        if show:
            print()

    def burst_mode(self, count: int = None) -> int:
        """Determine if we should do a burst of rapid actions.

        Returns number of rapid actions to perform (0 if no burst).
        """
        if random.random() < self.settings['burst_probability']:
            if count is None:
                min_burst, max_burst = self.settings['requests_per_burst']
                count = random.randint(min_burst, max_burst)
            return count
        return 0

    def schedule_action(self, target_time: datetime = None) -> datetime:
        """Schedule an action for a realistic time.

        Args:
            target_time: Optional target time (will add jitter)

        Returns:
            Scheduled datetime
        """
        if target_time is None:
            target_time = datetime.now()

        # Add jitter (1-30 minutes)
        jitter = timedelta(minutes=random.uniform(1, 30))
        scheduled = target_time + jitter

        # If working hours only, adjust
        if self.settings['working_hours_only']:
            while not self._is_working_time(scheduled):
                # Move to next working hour
                if scheduled.hour >= self.WORK_END:
                    # Move to next day
                    scheduled = scheduled.replace(
                        hour=self.WORK_START,
                        minute=random.randint(0, 59)
                    ) + timedelta(days=1)
                elif scheduled.hour < self.WORK_START:
                    scheduled = scheduled.replace(
                        hour=self.WORK_START,
                        minute=random.randint(0, 59)
                    )
                # Skip weekends
                while scheduled.weekday() >= 5:
                    scheduled += timedelta(days=1)

        return scheduled

    def _is_working_time(self, dt: datetime) -> bool:
        """Check if datetime is during working hours."""
        if dt.weekday() >= 5:
            return False
        return self.WORK_START <= dt.hour < self.WORK_END

    def randomize_order(self, items: list) -> list:
        """Randomize list order to avoid predictable patterns."""
        shuffled = items.copy()
        random.shuffle(shuffled)
        return shuffled

    def pick_subset(self, items: list, min_pct: float = 0.3, max_pct: float = 0.8) -> list:
        """Pick a random subset of items (simulating partial testing)."""
        count = int(len(items) * random.uniform(min_pct, max_pct))
        count = max(1, count)
        return random.sample(items, count)

    def should_retry(self, attempt: int, max_attempts: int = 3) -> bool:
        """Determine if we should retry after failure.

        Humans don't always retry immediately or at all.
        """
        if attempt >= max_attempts:
            return False

        # Decreasing probability of retry
        retry_prob = 0.8 ** attempt
        return random.random() < retry_prob

    def get_profile_description(self) -> str:
        """Get human-readable profile description."""
        descriptions = {
            'stealth': 'Maximum stealth - very slow, avoids detection',
            'normal': 'Balanced - human-like pacing with reasonable speed',
            'fast': 'Fast - quick but still somewhat natural',
            'aggressive': 'Aggressive - minimal delays, speed priority',
        }
        return descriptions.get(self.profile, 'Unknown profile')

    def status_report(self) -> dict:
        """Get current behavior status."""
        return {
            'profile': self.profile,
            'session_duration': str(datetime.now() - self.session_start),
            'action_count': self.action_count,
            'is_working_hours': self.is_working_hours(),
            'current_user_agent': self._user_agent,
            'session_id': self._session_id,
        }


# Preset instances
stealth_behavior = HumanBehavior('stealth')
normal_behavior = HumanBehavior('normal')
fast_behavior = HumanBehavior('fast')
aggressive_behavior = HumanBehavior('aggressive')

# Default instance
human = HumanBehavior('normal')


def with_human_delay(profile: str = 'normal'):
    """Decorator to add human-like delays to functions."""
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            behavior = HumanBehavior(profile)
            result = func(*args, **kwargs)
            behavior.wait(reason=func.__name__, show=False)
            return result
        return wrapper
    return decorator


if __name__ == "__main__":
    # Demo
    tui.banner("HUMAN BEHAVIOR SIMULATION", "Testing realistic activity patterns")

    print()
    for profile in ['stealth', 'normal', 'fast', 'aggressive']:
        behavior = HumanBehavior(profile)
        tui.section(f"Profile: {profile}")
        print(f"  {behavior.get_profile_description()}")
        print(f"  Base delay: {behavior.settings['base_delay']}s")
        print(f"  Break probability: {behavior.settings['break_probability']*100:.0f}%")
        print()

        # Show sample delays
        delays = [behavior.calculate_delay() for _ in range(5)]
        print(f"  Sample delays: {', '.join(f'{d:.2f}s' for d in delays)}")
        tui.section_end()
        print()

    # Interactive demo
    print()
    tui.info("Running live demo with 'normal' profile...")
    print()

    behavior = HumanBehavior('normal')
    for i in range(5):
        tui.spinner(f"Action {i+1}/5")
        behavior.wait(reason=f"action_{i+1}", show=True)

    print()
    tui.success("Demo complete")
    print()
    tui.keyvalue(behavior.status_report())
