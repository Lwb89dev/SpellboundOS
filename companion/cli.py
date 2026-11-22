"""CLI tool for the desktop SpellboundOS Watch Simulator."""
import argparse
import os

from companion.protocol import CallState
from companion.simulator import (
    KEY_SHORT_CLICK,
    SCREEN_QUICK_SETTINGS,
    SCREEN_WATCHFACE,
    WatchSimulator,
)


def generate_demo_screenshots(out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    sim = WatchSimulator()
    sim.establish_secure_link()
    sim.sync_time(1795255200, tz_offset_min=60)
    sim.lib.sim_inject_battery(82, True)
    sim.lib.sim_inject_hr(71)
    sim.lib.sim_inject_als(450)
    sim.simulate_walk(6)
    sim.send_notification(10, 'Signal', 'Marco', 'Ci vediamo alle 18?', actions=['OK', 'Arrivo'])
    sim.lib.sim_set_screen(SCREEN_WATCHFACE)
    sim.step(10)

    outputs: list[str] = []

    p1 = os.path.join(out_dir, '01_watchface.png')
    sim.save_png(p1)
    outputs.append(p1)

    sim.press_key(KEY_SHORT_CLICK, 0)
    sim.step(10)
    p2 = os.path.join(out_dir, '02_notifications.png')
    sim.save_png(p2)
    outputs.append(p2)

    sim.send_roadstr('Rotonda tra 350 m', 'Prendi la 2a uscita su Via Emilia (Arrivo 9 min)')
    sim.step(10)
    p3 = os.path.join(out_dir, '03_roadstr_nav.png')
    sim.save_png(p3)
    outputs.append(p3)

    sim.send_call(CallState.RINGING, 'Elena', '+39 340 123456')
    sim.step(10)
    p4 = os.path.join(out_dir, '04_incoming_call.png')
    sim.save_png(p4)
    outputs.append(p4)

    sim.send_call(CallState.IDLE)
    sim.lib.sim_set_screen(SCREEN_QUICK_SETTINGS)
    sim.step(10)
    p5 = os.path.join(out_dir, '05_quick_settings.png')
    sim.save_png(p5)
    outputs.append(p5)

    sim.lib.sim_set_screen(SCREEN_WATCHFACE)
    sim.lib.sim_set_aod(True)
    sim.step(10)
    p6 = os.path.join(out_dir, '06_aod.png')
    sim.save_png(p6)
    outputs.append(p6)

    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description='SpellboundOS Desktop Watch Simulator')
    parser.add_argument('--demo-dir', help='Render all 6 watch screens as PNGs into directory')
    parser.add_argument('--shell', help='Execute a SpellboundOS shell command and print output')
    args = parser.parse_args()

    if args.demo_dir:
        files = generate_demo_screenshots(args.demo_dir)
        for f in files:
            print(f'rendered: {f}')
    elif args.shell:
        sim = WatchSimulator()
        print(sim.shell(args.shell), end='')
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
