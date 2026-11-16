"""Tests for rayhunter-m2100, with adb replaced by an in-memory fake device."""
import importlib.machinery, importlib.util, io, pathlib, unittest
import random
import re
import sys

# The script has no .py extension; never cache its bytecode. A cached copy is
# keyed on mtime and size, so an edit of the same size within one second (as
# when a falsification is reverted) would silently run the old code.
sys.dont_write_bytecode = True
from contextlib import redirect_stdout

HERE = pathlib.Path(__file__).parent
loader = importlib.machinery.SourceFileLoader("rh", str(HERE / "rayhunter-m2100"))
spec = importlib.util.spec_from_loader("rh", loader)
rh = importlib.util.module_from_spec(spec)
loader.exec_module(rh)


class FakeDevice:
    """Plays the device's side of the file protocol."""

    def __init__(self, files=None, answer="ok gesture"):
        self.files = dict(files or {})
        self.answer = answer
        self.commands = []
        self.modes = {}

    def shell(self, cmd):
        self.commands.append(cmd)
        if cmd.startswith("test -e "):
            return "yes" if cmd.split()[2] in self.files else "no"
        if cmd.startswith("rm -f "):
            for p in cmd.split()[2:]:
                self.files.pop(p, None)
            return ""
        if cmd.startswith("echo ") and " > " in cmd:
            body, path = cmd[5:].split(" > ")
            self.files[path] = body
            if path == rh.REQUEST:
                self.files[rh.RESULT] = self.answer  # the daemon answers at once
            return ""
        if "/dev/urandom" in cmd:
            # the pipeline: write a random token to the .tmp, chmod, mv into place
            # the umask must come before anything is written, so the .tmp is
            # never readable by others, even if chmod or mv fails
            assert cmd.startswith("umask 077; "), cmd
            cmd = cmd[len("umask 077; "):]
            parts = [c.strip() for c in cmd.split("&&")]
            tmp = parts[0].split("> ")[-1]
            self.files[tmp] = "".join(random.choice("0123456789abcdef") for _ in range(64))
            for c in parts[1:]:
                w = c.split()
                if w[0] == "chmod":
                    self.modes[w[2]] = w[1]
                elif w[0] == "mv":
                    self.files[w[2]] = self.files.pop(w[1])
                    if w[1] in self.modes:
                        self.modes[w[2]] = self.modes.pop(w[1])
            return ""
        if cmd.startswith("cat "):
            path = cmd.split()[1]
            if path in self.files:
                return self.files[path]
            # Real adb shell merges stderr into stdout: a missing file is NOT
            # an empty answer, it's an error message.
            return "" if "2>/dev/null" in cmd else f"cat: can't open '{path}': No such file or directory"
        return ""


class Tests(unittest.TestCase):
    def run_cli(self, dev, *argv, confirm="y"):
        out = io.StringIO()
        with redirect_stdout(out):
            code = rh.main(list(argv), shell=dev.shell, ask=lambda _: confirm, sleep=lambda _: None)
        return code, out.getvalue()

    def test_status_reports_flags_only(self):
        dev = FakeDevice({rh.REVEAL: "salt = aa\nhash = bb\nlen = 4\n"})
        code, out = self.run_cli(dev, "status")
        self.assertEqual(code, 0)
        self.assertIn("reveal gesture: set", out)
        self.assertIn("panic PIN: not armed", out)
        self.assertNotIn("bb", out, "never prints secret material")

    def test_enroll_clears_old_result_then_requests_and_reports(self):
        dev = FakeDevice({rh.RESULT: "ok gesture"}, answer="ok gesture")
        code, out = self.run_cli(dev, "enroll", "gesture")
        self.assertEqual(code, 0)
        self.assertLess(dev.commands.index(f"rm -f {rh.RESULT}"),
                        next(i for i, c in enumerate(dev.commands) if rh.REQUEST in c and c.startswith("echo")))
        self.assertIn("perform your gesture", out)

    def test_enroll_failure_is_a_nonzero_exit(self):
        dev = FakeDevice(answer="ignored locked")
        code, out = self.run_cli(dev, "enroll", "gesture")
        self.assertNotEqual(code, 0)
        self.assertIn("locked", out)

    def test_enroll_pin_points_to_the_panel_and_sends_nothing(self):
        dev = FakeDevice()
        code, out = self.run_cli(dev, "enroll", "pin")
        self.assertNotEqual(code, 0)
        self.assertIn("settings", out)
        self.assertFalse(any(rh.REQUEST in c for c in dev.commands))

    def test_reset_asks_first_and_reloads(self):
        dev = FakeDevice({rh.REVEAL: "x"}, answer="ok reload")
        code, _ = self.run_cli(dev, "reset", "gesture", confirm="n")
        self.assertNotEqual(code, 0)
        self.assertIn(rh.REVEAL, dev.files, "declined: nothing deleted")
        code, _ = self.run_cli(dev, "reset", "gesture", confirm="y")
        self.assertEqual(code, 0)
        self.assertNotIn(rh.REVEAL, dev.files)
        self.assertTrue(any(c == f"echo reload > {rh.REQUEST}" for c in dev.commands))

    def test_pair_writes_a_tmp_then_moves_it_with_mode_600_and_prints_the_token_once(self):
        dev = FakeDevice()
        code, out = self.run_cli(dev, "pair")
        self.assertEqual(code, 0)
        token = dev.files[rh.TOKEN]
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", token))
        self.assertEqual(out.count(token), 1)
        self.assertIn("device_token", out)
        self.assertNotIn(rh.TOKEN + ".tmp", dev.files)
        self.assertEqual(dev.modes[rh.TOKEN], "600")
        gen = [c for c in dev.commands if "/dev/urandom" in c]
        self.assertEqual(len(gen), 1)
        self.assertIn(rh.TOKEN + ".tmp", gen[0])
        self.assertTrue(gen[0].startswith("umask 077; "))
        self.assertIn("chmod 600", gen[0])
        self.assertIn("mv ", gen[0])

    def test_pair_over_an_existing_token_asks_and_n_changes_nothing(self):
        old = "a" * 64
        dev = FakeDevice({rh.TOKEN: old})
        code, out = self.run_cli(dev, "pair", confirm="n")
        self.assertEqual(code, 1)
        self.assertEqual(dev.files[rh.TOKEN], old)
        self.assertFalse([c for c in dev.commands if "/dev/urandom" in c])
        self.assertNotIn(old, out)
        code, _ = self.run_cli(dev, "pair", confirm="y")
        self.assertEqual(code, 0)
        self.assertNotEqual(dev.files[rh.TOKEN], old)

    def test_a_missing_result_is_waited_for_not_taken_as_the_answer(self):
        # Found on the device: adb returned cat's error text, which the script
        # reported as the device's answer before enrolment had even started.
        dev = FakeDevice(answer="ok gesture")
        real_echo = dev.shell
        polls = []
        def slow_device(cmd):
            if cmd.startswith("echo ") and rh.REQUEST in cmd:
                dev.commands.append(cmd)
                dev.files[rh.REQUEST] = "gesture"  # no answer yet
                return ""
            if cmd.startswith("cat ") and rh.RESULT in cmd:
                polls.append(cmd)
                if len(polls) == 3:
                    dev.files[rh.RESULT] = "ok gesture"  # the device finishes
            return real_echo(cmd)
        out = io.StringIO()
        with redirect_stdout(out):
            code = rh.main(["enroll", "gesture"], shell=slow_device, ask=lambda _: "y", sleep=lambda _: None)
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("device: ok gesture", out.getvalue())
        self.assertGreaterEqual(len(polls), 3)

    def test_no_command_ever_contains_a_gesture_or_pin(self):
        dev = FakeDevice(answer="ok gesture")
        self.run_cli(dev, "enroll", "gesture")
        for c in dev.commands:
            self.assertNotRegex(c, r"\d{4,}")


if __name__ == "__main__":
    unittest.main()
