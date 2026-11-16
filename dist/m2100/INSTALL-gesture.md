# Setting your reveal gesture, panic PIN and profile

The M2100 always shows the stock Inseego screen. Until you set a reveal
gesture, nothing on the panel reveals Rayhunter.

## Quick reference

| To do this | Do this |
|---|---|
| Reveal Rayhunter | perform your gesture on the stock home screen |
| Open settings | hold the left edge (halfway down) for 3 s |
| Switch screens, or leave settings | hold a corner for 3 s (see "Moving around") |
| Hide Rayhunter | hold the corner of the screen you're on for 3 s |
| Change the gesture | settings, row 1 |
| Buzzer on/off | settings, row 2 |
| Fixed / Mobile profile | settings, row 3, then hold FIXED or MOBILE for 2 s |
| Change the panic PIN | settings, row 4 |
| Let Home Assistant switch to Fixed | `./rayhunter-m2100 pair`, over USB (see "Pair with Home Assistant") |
| Forgot the gesture or PIN | `./rayhunter-m2100 reset gesture` (or `pin`), over USB |

Settings and the profile screen close by themselves after 30 s untouched.

## Set the gesture

With the device connected over USB:

    ./rayhunter-m2100 enroll gesture

Wake the screen, then, on the device's **home screen**, perform your gesture,
pause for three seconds, and perform it again. Nothing you do is typed on the
computer, and the screen stays as it is: the LED tells you how it's going.

| LED | Meaning |
| --- | --- |
| one short blink | a move was recognised |
| two blinks | first time accepted: now do it again |
| one long glow | saved |
| three quick blinks | didn't work; it starts over by itself |

If the buzzer is on, it chirps along with the last three.

A gesture is 5 to 8 moves, from:

- a **swipe** up, down, left or right, anywhere on the screen
- a **touch** in the **top strip** (the bar with signal and battery), at its
  left, middle or right. Only *where* counts: a quick tap and a long press in
  the same place are the same move.

**Aim at the very top edge of the glass**, where it meets the frame: the
top-left corner, the top centre and the top-right corner. Aiming at the middle
of the strip, your finger tends to land just below it, and that touch doesn't
count. Avoid the two points a third and two thirds of the way across, where
the zones meet: a touch there is ignored rather than guessed.

Touches anywhere else don't count: the stock screen reacts to them.

## Perform it from the home screen

If you're not sure you're on the home screen, tap the top-right corner first.
On any other screen that's the home button; on the home screen it does nothing.

## Set the panic PIN

The PIN is set on the device itself, after your gesture:

1. Reveal Rayhunter with your gesture.
2. Hold the left edge of the screen for three seconds to open settings.
3. Tap the bottom row ("set panic PIN").
4. Enter 6 to 8 digits on the invisible 3×3 pad (hold each for half a second),
   pause, then enter them again. The screen shows "Saved".

## Moving around inside Rayhunter

Your gesture always opens the status screen. From there, hold a corner for
three seconds to switch screens:

| Corner | Screen |
|---|---|
| top-left | cell log |
| top-right | orca |
| bottom-left | EFF logo |
| bottom-right | status |

Holding the corner of the screen you're already on hides Rayhunter and brings
back the stock screen.

The corners also take you out of settings and the profile screen: hold one for
three seconds and you go straight to that corner's screen (bottom-right for
status). Leaving this way never hides Rayhunter, even if it's the screen you
came from.

## Settings

Reveal Rayhunter and hold the left edge (halfway down) for three seconds.
Settings has four rows, top to bottom:

| Row | Tap it to |
|---|---|
| 1. set reveal gesture | change the gesture |
| 2. buzzer is ON / OFF | switch Rayhunter's own sounds (detection beeps and these signals) |
| 3. Profile: FIXED / MOBILE | open the profile screen |
| 4. set panic PIN | change the PIN |

Aim at the middle of a row: a tap in the narrow gap between two rows does
nothing.

## Change the gesture or PIN later

Open settings and tap row 1 (gesture) or row 4 (PIN). You'll perform the current
one first. For the gesture, Rayhunter's screen hides and you perform it on the
stock screen, with the same LED signals as above.

## Fixed or Mobile profile

The profile decides whether the device uses cellular data:

| Profile | For | What it does |
|---|---|---|
| **FIXED** | the cabinet, on the Home Assistant box | cellular data off, Wi-Fi hotspot off, and a firewall that blocks anything leaving over cellular (IPv4 and IPv6). No ntfy alerts: there's no way out to send them. Alerts still show on the screen and in Home Assistant. |
| **MOBILE** | carrying it on its own | cellular data on, so ntfy alerts go out. Sends one "Rayhunter: mobile profile active" once data is up (allow a minute or two). |

To switch: open settings, tap row 3, then **hold FIXED (top) or MOBILE (bottom)
for two seconds**. The line between them says "switching...", then the one you
chose turns green and says "(current)". If it says "switch failed", nothing was
saved: hold again to retry.

Holding the profile that's already current applies it again. Use this if the
device has drifted, for example if something turned cellular data back on while
it's in Fixed (Home Assistant warns you about this).

The device keeps its profile across restarts. After a reboot it puts the
profile back by itself, which takes two to three minutes because it waits for
the cellular modem to start.

On the Home Assistant box, when the device asks how to use USB, choose
**"USB only"**. ("Charge only" connects nothing.)

## Pair with Home Assistant

The Home Assistant add-on has a Fixed button. It can do one thing to the
device: move it to the Fixed profile. It can't switch to Mobile or change
anything else. To allow that, make a token over USB:

    ./rayhunter-m2100 pair

It prints a long code once. Paste it into the add-on's **device_token**
setting. The device keeps a copy that only it can read.

Running `pair` again asks first, because the new code replaces the old one and
the add-on stops working until you paste the new one. The device accepts one
request every ten seconds.

## Forgot it?

    ./rayhunter-m2100 reset gesture     # or: reset pin

This needs the device on USB, which is the point.
