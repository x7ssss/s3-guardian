import { describe, it, expect, vi } from "vitest";
import {
  ANSI,
  enterAltScreen,
  exitAltScreen,
  hideCursor,
  showCursor,
  clearScreen,
  moveTo,
  bold,
  dim,
  green,
  red,
  yellow,
  cyan,
  gray,
  inverse,
  colors,
  parseKeySequence,
  enableRawMode,
  setupTerminalHygiene,
  TerminalStream,
} from "../src/tui/terminal.js";
import { EventEmitter } from "node:events";

describe("ANSI Terminal Primitives", () => {
  it("defines standard ANSI escape codes for alt screen, cursor, and colors", () => {
    expect(ANSI.ENTER_ALT_SCREEN).toBe("\x1b[?1049h");
    expect(ANSI.EXIT_ALT_SCREEN).toBe("\x1b[?1049l");
    expect(ANSI.HIDE_CURSOR).toBe("\x1b[?25l");
    expect(ANSI.SHOW_CURSOR).toBe("\x1b[?25h");
    expect(ANSI.CLEAR_SCREEN).toBe("\x1b[2J\x1b[H");
    expect(ANSI.RESET).toBe("\x1b[0m");
  });

  it("writes alt screen commands to provided stream", () => {
    const chunks: string[] = [];
    const mockStream: TerminalStream = {
      write: (c: string) => chunks.push(c),
    };

    enterAltScreen(mockStream);
    expect(chunks).toContain(ANSI.ENTER_ALT_SCREEN);

    chunks.length = 0;
    exitAltScreen(mockStream);
    expect(chunks).toContain(ANSI.EXIT_ALT_SCREEN);
  });

  it("writes cursor show/hide and clearScreen commands to stream", () => {
    const chunks: string[] = [];
    const mockStream: TerminalStream = {
      write: (c: string) => chunks.push(c),
    };

    hideCursor(mockStream);
    expect(chunks).toContain(ANSI.HIDE_CURSOR);

    chunks.length = 0;
    showCursor(mockStream);
    expect(chunks).toContain(ANSI.SHOW_CURSOR);

    chunks.length = 0;
    clearScreen(mockStream);
    expect(chunks).toContain(ANSI.CLEAR_SCREEN);
  });

  it("writes 1-indexed moveTo escape sequences with clamping", () => {
    const chunks: string[] = [];
    const mockStream: TerminalStream = {
      write: (c: string) => chunks.push(c),
    };

    moveTo(5, 12, mockStream);
    expect(chunks).toEqual(["\x1b[5;12H"]);

    chunks.length = 0;
    moveTo(0, -3, mockStream);
    expect(chunks).toEqual(["\x1b[1;1H"]);
  });

  it("formats text styling primitives with matching reset codes", () => {
    expect(bold("text")).toBe("\x1b[1mtext\x1b[0m");
    expect(dim("text")).toBe("\x1b[2mtext\x1b[0m");
    expect(green("text")).toBe("\x1b[32mtext\x1b[0m");
    expect(red("text")).toBe("\x1b[31mtext\x1b[0m");
    expect(yellow("text")).toBe("\x1b[33mtext\x1b[0m");
    expect(cyan("text")).toBe("\x1b[36mtext\x1b[0m");
    expect(gray("text")).toBe("\x1b[90mtext\x1b[0m");
    expect(inverse("text")).toBe("\x1b[7mtext\x1b[0m");
    expect(colors.green(123)).toBe("\x1b[32m123\x1b[0m");
  });
});

describe("Key Sequence Parser (parseKeySequence)", () => {
  it("parses arrow key sequences", () => {
    expect(parseKeySequence("\x1b[A")).toEqual({ raw: "\x1b[A", name: "up", ctrl: false });
    expect(parseKeySequence("\x1b[B")).toEqual({ raw: "\x1b[B", name: "down", ctrl: false });
    expect(parseKeySequence("\x1b[C")).toEqual({ raw: "\x1b[C", name: "right", ctrl: false });
    expect(parseKeySequence("\x1b[D")).toEqual({ raw: "\x1b[D", name: "left", ctrl: false });
  });

  it("parses enter, escape, tab, and backspace", () => {
    expect(parseKeySequence("\r")).toEqual({ raw: "\r", name: "enter", ctrl: false });
    expect(parseKeySequence("\n")).toEqual({ raw: "\n", name: "enter", ctrl: false });
    expect(parseKeySequence("\r\n")).toEqual({ raw: "\r\n", name: "enter", ctrl: false });
    expect(parseKeySequence("\x1b")).toEqual({ raw: "\x1b", name: "escape", ctrl: false });
    expect(parseKeySequence("\t")).toEqual({ raw: "\t", name: "tab", ctrl: false });
    expect(parseKeySequence("\x7f")).toEqual({ raw: "\x7f", name: "backspace", ctrl: false });
    expect(parseKeySequence("\x08")).toEqual({ raw: "\x08", name: "backspace", ctrl: false });
  });

  it("parses ctrl+c sequence", () => {
    expect(parseKeySequence("\x03")).toEqual({ raw: "\x03", name: "ctrl+c", ctrl: true });
  });

  it("parses regular character keys and Buffer inputs", () => {
    expect(parseKeySequence("q")).toEqual({ raw: "q", name: "q", ctrl: false });
    expect(parseKeySequence("Q")).toEqual({ raw: "Q", name: "q", ctrl: false });
    expect(parseKeySequence("p")).toEqual({ raw: "p", name: "p", ctrl: false });
    expect(parseKeySequence("r")).toEqual({ raw: "r", name: "r", ctrl: false });
    expect(parseKeySequence("j")).toEqual({ raw: "j", name: "j", ctrl: false });
    expect(parseKeySequence("k")).toEqual({ raw: "k", name: "k", ctrl: false });

    const buf = Buffer.from("\x1b[A", "utf8");
    expect(parseKeySequence(buf)).toEqual({ raw: "\x1b[A", name: "up", ctrl: false });
  });
});

describe("Raw Mode Management (enableRawMode)", () => {
  it("enables raw mode, delivers parsed keys, and disables raw mode on cleanup", () => {
    const fakeStdin = new EventEmitter() as any;
    fakeStdin.isTTY = true;
    let rawEnabled = false;
    fakeStdin.setRawMode = (mode: boolean) => {
      rawEnabled = mode;
    };
    fakeStdin.resume = vi.fn();
    fakeStdin.pause = vi.fn();
    fakeStdin.setEncoding = vi.fn();

    const receivedKeys: string[] = [];
    const cleanup = enableRawMode((key) => {
      receivedKeys.push(key);
    }, fakeStdin);

    expect(rawEnabled).toBe(true);
    expect(fakeStdin.resume).toHaveBeenCalled();
    expect(fakeStdin.setEncoding).toHaveBeenCalledWith("utf8");

    fakeStdin.emit("data", "\x1b[B"); // down
    fakeStdin.emit("data", "j");
    fakeStdin.emit("data", "\r"); // enter

    expect(receivedKeys).toEqual(["down", "j", "enter"]);

    cleanup();
    expect(rawEnabled).toBe(false);
    expect(fakeStdin.pause).toHaveBeenCalled();

    // Emitting data after cleanup does not trigger callback
    fakeStdin.emit("data", "k");
    expect(receivedKeys).toEqual(["down", "j", "enter"]);
  });

  it("is idempotent on repeated cleanup calls", () => {
    const fakeStdin = new EventEmitter() as any;
    fakeStdin.isTTY = true;
    let setRawModeCalls = 0;
    fakeStdin.setRawMode = () => {
      setRawModeCalls++;
    };
    fakeStdin.resume = vi.fn();
    fakeStdin.pause = vi.fn();
    fakeStdin.setEncoding = vi.fn();

    const cleanup = enableRawMode(() => {}, fakeStdin);
    expect(setRawModeCalls).toBe(1);

    cleanup();
    expect(setRawModeCalls).toBe(2);

    cleanup();
    expect(setRawModeCalls).toBe(2);
  });
});

describe("Terminal Hygiene (setupTerminalHygiene)", () => {
  it("enters alt screen and hides cursor on setup, restores primary screen and cursor on cleanup", () => {
    const writes: string[] = [];
    const mockStream: TerminalStream = {
      write: (s: string) => writes.push(s),
    };

    const cleanup = setupTerminalHygiene(mockStream);

    expect(writes).toContain(ANSI.ENTER_ALT_SCREEN);
    expect(writes).toContain(ANSI.HIDE_CURSOR);

    writes.length = 0;
    cleanup();

    expect(writes).toContain(ANSI.SHOW_CURSOR);
    expect(writes).toContain(ANSI.EXIT_ALT_SCREEN);

    // Repeated cleanup is a no-op
    writes.length = 0;
    cleanup();
    expect(writes).toEqual([]);
  });

  it("registers and unregisters process signal listeners", () => {
    const mockStream: TerminalStream = { write: () => {} };

    const initialSigintCount = process.listenerCount("SIGINT");
    const cleanup = setupTerminalHygiene(mockStream);

    expect(process.listenerCount("SIGINT")).toBe(initialSigintCount + 1);

    cleanup();
    expect(process.listenerCount("SIGINT")).toBe(initialSigintCount);
  });
});
