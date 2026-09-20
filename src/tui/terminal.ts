/**
 * Zero-dependency native ANSI terminal helper primitives and raw mode management.
 * Follows strict terminal hygiene: alternate screen buffer (\x1b[?1049h) and cursor control.
 */

export interface TerminalStream {
  write: (chunk: string) => unknown;
}

export const ANSI = {
  ENTER_ALT_SCREEN: "\x1b[?1049h",
  EXIT_ALT_SCREEN: "\x1b[?1049l",
  HIDE_CURSOR: "\x1b[?25l",
  SHOW_CURSOR: "\x1b[?25h",
  CLEAR_SCREEN: "\x1b[2J\x1b[H",
  CLEAR_LINE: "\x1b[2K",
  RESET: "\x1b[0m",
  BOLD: "\x1b[1m",
  DIM: "\x1b[2m",
  UNDERLINE: "\x1b[4m",
  INVERSE: "\x1b[7m",
  RED: "\x1b[31m",
  GREEN: "\x1b[32m",
  YELLOW: "\x1b[33m",
  BLUE: "\x1b[34m",
  MAGENTA: "\x1b[35m",
  CYAN: "\x1b[36m",
  WHITE: "\x1b[37m",
  GRAY: "\x1b[90m",
  BG_BLUE: "\x1b[44m",
  BG_CYAN: "\x1b[46m",
} as const;

export function enterAltScreen(stream: TerminalStream = process.stdout): void {
  stream.write(ANSI.ENTER_ALT_SCREEN);
}

export function exitAltScreen(stream: TerminalStream = process.stdout): void {
  stream.write(ANSI.EXIT_ALT_SCREEN);
}

export function hideCursor(stream: TerminalStream = process.stdout): void {
  stream.write(ANSI.HIDE_CURSOR);
}

export function showCursor(stream: TerminalStream = process.stdout): void {
  stream.write(ANSI.SHOW_CURSOR);
}

export function clearScreen(stream: TerminalStream = process.stdout): void {
  stream.write(ANSI.CLEAR_SCREEN);
}

export function moveTo(
  row: number,
  col: number,
  stream: TerminalStream = process.stdout
): void {
  stream.write(`\x1b[${Math.max(1, Math.floor(row))};${Math.max(1, Math.floor(col))}H`);
}

// ─── Text Styling Primitives ──────────────────────────────────────────────────

export const bold = (text: string | number): string =>
  `${ANSI.BOLD}${text}${ANSI.RESET}`;

export const dim = (text: string | number): string =>
  `${ANSI.DIM}${text}${ANSI.RESET}`;

export const green = (text: string | number): string =>
  `${ANSI.GREEN}${text}${ANSI.RESET}`;

export const red = (text: string | number): string =>
  `${ANSI.RED}${text}${ANSI.RESET}`;

export const yellow = (text: string | number): string =>
  `${ANSI.YELLOW}${text}${ANSI.RESET}`;

export const cyan = (text: string | number): string =>
  `${ANSI.CYAN}${text}${ANSI.RESET}`;

export const gray = (text: string | number): string =>
  `${ANSI.GRAY}${text}${ANSI.RESET}`;

export const inverse = (text: string | number): string =>
  `${ANSI.INVERSE}${text}${ANSI.RESET}`;

export const colors = {
  bold,
  dim,
  green,
  red,
  yellow,
  cyan,
  gray,
  inverse,
};

// ─── Key Sequence Parsing ─────────────────────────────────────────────────────

export interface KeyInfo {
  raw: string;
  name: string;
  ctrl: boolean;
}

/**
 * Parses raw terminal byte inputs into normalized key identifiers.
 */
export function parseKeySequence(chunk: Buffer | string): KeyInfo {
  const str = typeof chunk === "string" ? chunk : chunk.toString("utf8");

  if (str === "\x1b[A") {
    return { raw: str, name: "up", ctrl: false };
  }
  if (str === "\x1b[B") {
    return { raw: str, name: "down", ctrl: false };
  }
  if (str === "\x1b[C") {
    return { raw: str, name: "right", ctrl: false };
  }
  if (str === "\x1b[D") {
    return { raw: str, name: "left", ctrl: false };
  }
  if (str === "\r" || str === "\n" || str === "\r\n") {
    return { raw: str, name: "enter", ctrl: false };
  }
  if (str === "\x03") {
    return { raw: str, name: "ctrl+c", ctrl: true };
  }
  if (str === "\x1b") {
    return { raw: str, name: "escape", ctrl: false };
  }
  if (str === "\t") {
    return { raw: str, name: "tab", ctrl: false };
  }
  if (str === "\x7f" || str === "\x08") {
    return { raw: str, name: "backspace", ctrl: false };
  }

  const lower = str.toLowerCase();
  return { raw: str, name: lower, ctrl: false };
}

/**
 * Configures stdin for raw unbuffered keyboard navigation.
 * Returns a cleanup teardown function that restores standard mode.
 */
export function enableRawMode(
  onKeypress: (key: string, keyInfo?: KeyInfo) => void,
  stdin: NodeJS.ReadStream = process.stdin
): () => void {
  const isTTY = Boolean(stdin.isTTY);

  if (isTTY && typeof stdin.setRawMode === "function") {
    stdin.setRawMode(true);
  }

  stdin.resume();
  stdin.setEncoding("utf8");

  const onData = (chunk: Buffer | string) => {
    const keyInfo = parseKeySequence(chunk);
    onKeypress(keyInfo.name, keyInfo);
  };

  stdin.on("data", onData);

  let cleanedUp = false;
  return () => {
    if (cleanedUp) return;
    cleanedUp = true;
    stdin.removeListener("data", onData);
    if (isTTY && typeof stdin.setRawMode === "function") {
      stdin.setRawMode(false);
    }
    stdin.pause();
  };
}

/**
 * Ensures clean terminal hygiene:
 *  - Enters alternate screen buffer.
 *  - Hides cursor.
 *  - Traps exit, SIGINT, SIGTERM, and uncaughtException to cleanly restore
 *    the primary screen and cursor.
 */
export function setupTerminalHygiene(stream: TerminalStream = process.stdout): () => void {
  enterAltScreen(stream);
  hideCursor(stream);

  let restored = false;
  const restore = () => {
    if (restored) return;
    restored = true;
    showCursor(stream);
    exitAltScreen(stream);
  };

  const onSignal = () => {
    restore();
    process.exit(0);
  };

  const onUncaught = (err: unknown) => {
    restore();
    console.error("Uncaught exception in TUI:", err);
    process.exit(1);
  };

  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  process.once("uncaughtException", onUncaught);

  return () => {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    process.removeListener("uncaughtException", onUncaught);
    restore();
  };
}
