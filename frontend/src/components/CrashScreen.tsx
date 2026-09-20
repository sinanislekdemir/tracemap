import { useMemo, useState } from 'react';

interface CrashScreenProps {
  title: string;
  error: unknown;
  componentStack?: string;
  /** Render as a full-window overlay instead of filling the page. */
  overlay?: boolean;
  onRetry?: () => void;
  onDismiss?: () => void;
}

// buildCrashReport assembles everything worth sharing: the error, its stack,
// the React component stack and the environment it happened in.
export function buildCrashReport(title: string, error: unknown, componentStack?: string): string {
  const lines: string[] = [];
  lines.push(`=== ${title} ===`);
  lines.push(`time:  ${new Date().toISOString()}`);
  if (typeof location !== 'undefined') {
    lines.push(`url:   ${location.href}`);
  }
  if (typeof navigator !== 'undefined') {
    lines.push(`agent: ${navigator.userAgent}`);
  }
  lines.push('');

  if (error instanceof Error) {
    lines.push(`${error.name}: ${error.message}`);
    if (error.stack) {
      lines.push('', error.stack);
    }
  } else if (typeof error === 'string') {
    lines.push(error);
  } else {
    try {
      lines.push(JSON.stringify(error, null, 2));
    } catch {
      lines.push(String(error));
    }
  }

  if (componentStack) {
    lines.push('', 'component stack:', componentStack.trimEnd());
  }
  return lines.join('\n');
}

// copyText prefers the async clipboard API and falls back to a hidden textarea,
// which the WebKit webview may require.
async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // fall through to the legacy path
  }
  try {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.top = '-1000px';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(area);
    return ok;
  } catch {
    return false;
  }
}

const CrashScreen = ({
  title,
  error,
  componentStack,
  overlay,
  onRetry,
  onDismiss,
}: CrashScreenProps) => {
  const report = useMemo(
    () => buildCrashReport(title, error, componentStack),
    [title, error, componentStack],
  );
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    void copyText(report).then((ok) => {
      if (ok) {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1600);
      }
    });
  };

  return (
    <div className={`crash${overlay ? ' crash--overlay' : ''}`}>
      <div className="crash-panel">
        <div className="crash-title">{title}</div>
        <div className="crash-hint">
          Copy the traceback below and share it to get help. It includes the stack, the React
          component tree and your environment.
        </div>
        <pre className="crash-trace selectable">{report}</pre>
        <div className="crash-actions">
          <button type="button" className="btn" onClick={handleCopy}>
            {copied ? 'Copied' : 'Copy traceback'}
          </button>
          {onDismiss && (
            <button type="button" className="btn" onClick={onDismiss}>
              Dismiss
            </button>
          )}
          {onRetry && (
            <button type="button" className="btn btn--primary" onClick={onRetry}>
              Retry
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default CrashScreen;
