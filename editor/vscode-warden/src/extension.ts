// Warden VS Code extension entry point.
//
// Activates on first .warden file open. Spawns warden-lsp as a stdio
// language client. The extension itself contains no language logic —
// every syntactic and semantic feature comes from the LSP server,
// keeping the TypeScript surface tiny (~100 lines) and free of drift.

import {
  workspace,
  window,
  ExtensionContext,
  StatusBarAlignment,
  StatusBarItem,
} from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
  State,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let status: StatusBarItem | undefined;

export async function activate(context: ExtensionContext): Promise<void> {
  const cfg = workspace.getConfiguration("warden");
  if (cfg.get<boolean>("lsp.disable", false)) {
    return;
  }

  // Default: spawn `warden lsp` — the unified CLI subcommand. The
  // standalone `warden-lsp` binary works equivalently; users can swap by
  // setting warden.lsp.command to ["warden-lsp"].
  const cmd = cfg.get<string[]>("lsp.command", ["warden", "lsp"]);
  if (!cmd.length) {
    void window.showErrorMessage(
      "warden.lsp.command is empty — set it to [\"warden\", \"lsp\"] or [\"warden-lsp\"]."
    );
    return;
  }
  const command = cmd[0];
  const args = cmd.slice(1);

  const serverOptions: ServerOptions = {
    run: { command, args, transport: TransportKind.stdio },
    debug: { command, args, transport: TransportKind.stdio },
  };

  const trace = cfg.get<string>("lsp.trace", "off");
  const traceChannel =
    trace === "off" ? undefined : window.createOutputChannel("Warden LSP (Trace)");

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "warden" },
      { scheme: "untitled", language: "warden" },
    ],
    synchronize: {
      fileEvents: workspace.createFileSystemWatcher("**/*.warden"),
    },
    outputChannelName: "Warden LSP",
    traceOutputChannel: traceChannel,
  };

  status = window.createStatusBarItem(StatusBarAlignment.Right, 100);
  status.text = "$(loading~spin) Warden LSP";
  status.tooltip = "Warden language server is starting…";
  status.show();
  context.subscriptions.push(status);

  client = new LanguageClient("warden", "Warden", serverOptions, clientOptions);

  client.onDidChangeState((event) => {
    if (!status) {
      return;
    }
    switch (event.newState) {
      case State.Running:
        status.text = "$(check) Warden LSP";
        status.tooltip = "Warden language server is running.";
        break;
      case State.Starting:
        status.text = "$(loading~spin) Warden LSP";
        status.tooltip = "Warden language server is starting…";
        break;
      case State.Stopped:
        status.text = "$(error) Warden LSP";
        status.tooltip =
          "Warden language server has stopped. Check 'warden.lsp.path' in settings.";
        break;
    }
  });

  try {
    await client.start();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    void window.showErrorMessage(
      `Warden LSP failed to start: ${msg}. ` +
        "Set 'warden.lsp.path' in your settings, or install warden-lsp on PATH " +
        "(e.g. `go install github.com/xraph/warden/cmd/warden-lsp@latest`).",
    );
    if (status) {
      status.text = "$(error) Warden LSP";
    }
  }
}

export function deactivate(): Thenable<void> | undefined {
  return client?.stop();
}
