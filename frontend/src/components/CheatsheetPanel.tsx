import { useState } from 'react';
import type { Cheatsheet } from '../cheatsheets';

interface CheatsheetPanelProps {
  sheet: Cheatsheet;
}

const CheatsheetPanel = ({ sheet }: CheatsheetPanelProps) => {
  const [copied, setCopied] = useState<string | null>(null);

  const copy = (command: string) => {
    if (!command) {
      return;
    }
    navigator.clipboard?.writeText(command).then(
      () => {
        setCopied(command);
        window.setTimeout(() => setCopied((current) => (current === command ? null : current)), 1200);
      },
      () => undefined,
    );
  };

  return (
    <div className="cheatsheet">
      <div className="cheatsheet-head">
        <div className="cheatsheet-head-row">
          <span className="cheatsheet-proto">{sheet.protocol}</span>
          <span className="cheatsheet-port">{sheet.port}</span>
        </div>
        <p className="cheatsheet-summary selectable">{sheet.summary}</p>
      </div>
      <div className="cheatsheet-body">
        {sheet.groups.map((group) => (
          <section className="cheatsheet-group" key={group.name}>
            <div className="cheatsheet-group-name">{group.name}</div>
            {group.commands.map((entry, index) => (
              <div className="cheatsheet-cmd" key={`${group.name}-${entry.label}-${index}`}>
                <div className="cheatsheet-cmd-main">
                  <span className="cheatsheet-label selectable">{entry.label}</span>
                  <code
                    className={`cheatsheet-code selectable${entry.command ? '' : ' is-empty'}`}
                    onClick={() => copy(entry.command)}
                    title={entry.command ? 'Click to copy' : undefined}
                  >
                    {entry.command || '↵ blank line'}
                  </code>
                </div>
                <div className="cheatsheet-cmd-side">
                  {entry.note && <span className="cheatsheet-note selectable">{entry.note}</span>}
                  <button
                    type="button"
                    className="cheatsheet-copy"
                    onClick={() => copy(entry.command)}
                    disabled={!entry.command}
                    title="Copy command"
                  >
                    {copied === entry.command && entry.command ? 'COPIED' : 'COPY'}
                  </button>
                </div>
              </div>
            ))}
          </section>
        ))}
      </div>
    </div>
  );
};

export default CheatsheetPanel;
