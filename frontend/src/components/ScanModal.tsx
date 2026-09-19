import { useState } from 'react';
import { PickWordlist } from '../../wailsjs/go/main/App';
import Modal from './Modal';
import { useEscape } from '../useEscape';
import type { ScanOptions } from '../types';

interface ScanModalProps {
  open: boolean;
  domain: string;
  maxHops: number;
  onDomainChange: (value: string) => void;
  onMaxHopsChange: (value: number) => void;
  onCancel: () => void;
  onConfirm: (options: ScanOptions) => void;
}

const BASIC: ScanOptions = {
  expandNs: true,
  bruteForce: false,
  wordlistPath: '',
  ptr: false,
  sweep24: false,
  services: false,
  crawl: false,
  crawlMaxPages: 25,
  autoTrace: true,
  maxTargets: 12,
};

const STANDARD: ScanOptions = {
  expandNs: true,
  bruteForce: true,
  wordlistPath: '',
  ptr: true,
  sweep24: false,
  services: true,
  crawl: true,
  crawlMaxPages: 25,
  autoTrace: false,
  maxTargets: 24,
};

const DEEP: ScanOptions = {
  expandNs: true,
  bruteForce: true,
  wordlistPath: '',
  ptr: true,
  sweep24: true,
  services: true,
  crawl: true,
  crawlMaxPages: 100,
  autoTrace: true,
  maxTargets: 200,
};

const DEEP_MAX_HOPS = 100;

const ScanModal = ({
  open,
  domain,
  maxHops,
  onDomainChange,
  onMaxHopsChange,
  onCancel,
  onConfirm,
}: ScanModalProps) => {
  const [options, setOptions] = useState<ScanOptions>(STANDARD);

  useEscape(open, onCancel);

  if (!open) {
    return null;
  }

  const set = (patch: Partial<ScanOptions>) => setOptions((previous) => ({ ...previous, ...patch }));
  const toggle = (key: keyof ScanOptions) => set({ [key]: !options[key] } as Partial<ScanOptions>);

  const handleBrowse = async () => {
    try {
      const path = await PickWordlist();
      if (path) {
        set({ wordlistPath: path });
      }
    } catch {
      // A missing dialog just means the user types the path instead.
    }
  };

  return (
    <Modal
      title="SCAN OPTIONS"
      subtitle="DNS records, subdomain discovery and tracing"
      ariaLabel="Scan options"
      onClose={onCancel}
      footer={
        <>
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn--primary"
            disabled={domain.trim() === ''}
            onClick={() => onConfirm(options)}
          >
            Start scan
          </button>
        </>
      }
    >
          <div className="scan-fields">
            <div className="field field--target">
              <label className="field-label" htmlFor="scan-domain">
                DOMAIN
              </label>
              <div className="input-wrap">
                <span className="input-prompt">›</span>
                <input
                  id="scan-domain"
                  className="input selectable"
                  type="text"
                  value={domain}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="domain to scan"
                  onChange={(event) => onDomainChange(event.target.value)}
                />
              </div>
            </div>
            <div className="field">
              <label className="field-label" htmlFor="scan-hops">
                MAX HOPS
              </label>
              <input
                id="scan-hops"
                className="input input--num selectable"
                type="number"
                min={1}
                max={100}
                value={maxHops}
                onChange={(event) => onMaxHopsChange(Number(event.target.value) || 30)}
              />
            </div>
          </div>

          <div className="scan-presets">
            <button type="button" className="btn btn--ghost" onClick={() => setOptions(BASIC)}>
              Basic
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => setOptions(STANDARD)}>
              Standard
            </button>
            <button
              type="button"
              className="btn btn--ghost"
              onClick={() => {
                setOptions(DEEP);
                onMaxHopsChange(DEEP_MAX_HOPS);
              }}
            >
              Deep
            </button>
          </div>

          <div className="scan-group">
            <div className="scan-group-title">DNS RECORDS</div>
            <label className="scan-option">
              <input
                type="checkbox"
                checked={options.expandNs}
                onChange={() => toggle('expandNs')}
              />
              <span className="scan-option-main">
                <span className="scan-option-label">Follow nameservers</span>
                <span className="scan-option-hint">Recursively expand NS and the SOA primary nameserver</span>
              </span>
            </label>
          </div>

          <div className="scan-group">
            <div className="scan-group-title">SUBDOMAIN DISCOVERY</div>
            <label className="scan-option">
              <input
                type="checkbox"
                checked={options.bruteForce}
                onChange={() => toggle('bruteForce')}
              />
              <span className="scan-option-main">
                <span className="scan-option-label">Brute force · 1000 names</span>
                <span className="scan-option-hint">Probe the embedded list of common subdomain labels</span>
              </span>
            </label>
            {options.bruteForce && (
              <div className="scan-wordlist">
                <label className="field-label" htmlFor="scan-wordlist">
                  WORDLIST (OPTIONAL)
                </label>
                <div className="scan-wordlist-row">
                  <input
                    id="scan-wordlist"
                    className="input selectable"
                    type="text"
                    value={options.wordlistPath}
                    spellCheck={false}
                    autoComplete="off"
                    placeholder="embedded 1000-name list"
                    onChange={(event) => set({ wordlistPath: event.target.value })}
                  />
                  <button type="button" className="btn btn--ghost" onClick={handleBrowse}>
                    Browse
                  </button>
                </div>
                <span className="scan-option-hint">
                  Point brute force at a newline-delimited file of labels instead of the embedded list
                </span>
              </div>
            )}
            <label className="scan-option">
              <input type="checkbox" checked={options.ptr} onChange={() => toggle('ptr')} />
              <span className="scan-option-main">
                <span className="scan-option-label">Reverse DNS (PTR)</span>
                <span className="scan-option-hint">Resolve discovered IPs back to in-domain names</span>
              </span>
            </label>
            <label className="scan-option">
              <input type="checkbox" checked={options.sweep24} onChange={() => toggle('sweep24')} />
              <span className="scan-option-main">
                <span className="scan-option-label">Sweep /24 netblocks</span>
                <span className="scan-option-hint">Reverse-resolve the whole /24 around each IPv4 (slow)</span>
              </span>
            </label>
            <label className="scan-option">
              <input
                type="checkbox"
                checked={options.services}
                onChange={() => toggle('services')}
              />
              <span className="scan-option-main">
                <span className="scan-option-label">Services (SPF / DMARC / SRV)</span>
                <span className="scan-option-hint">Extract hostnames from TXT and SRV records</span>
              </span>
            </label>
          </div>

          <div className="scan-group">
            <div className="scan-group-title">WEB CRAWL</div>
            <label className="scan-option">
              <input type="checkbox" checked={options.crawl} onChange={() => toggle('crawl')} />
              <span className="scan-option-main">
                <span className="scan-option-label">Frontpage + 1 level</span>
                <span className="scan-option-hint">
                  Fetch the homepage and its links with a browser agent, plus robots.txt and sitemap.xml, to
                  discover pages and subdomains
                </span>
              </span>
            </label>
            {options.crawl && (
              <div className="scan-cap">
                <label className="field-label" htmlFor="scan-crawl-pages">
                  MAX PAGES
                </label>
                <input
                  id="scan-crawl-pages"
                  className="input input--num selectable"
                  type="number"
                  min={1}
                  max={200}
                  value={options.crawlMaxPages}
                  onChange={(event) => set({ crawlMaxPages: Number(event.target.value) || 25 })}
                />
              </div>
            )}
          </div>

          <div className="scan-group">
            <div className="scan-group-title">TARGETS</div>
            <label className="scan-option">
              <input
                type="radio"
                name="scan-mode"
                checked={!options.autoTrace}
                onChange={() => set({ autoTrace: false })}
              />
              <span className="scan-option-main">
                <span className="scan-option-label">Review and pick</span>
                <span className="scan-option-hint">Trace records now, then choose subdomains to trace</span>
              </span>
            </label>
            <label className="scan-option">
              <input
                type="radio"
                name="scan-mode"
                checked={options.autoTrace}
                onChange={() => set({ autoTrace: true })}
              />
              <span className="scan-option-main">
                <span className="scan-option-label">Auto-trace</span>
                <span className="scan-option-hint">Trace records and discovered subdomains automatically</span>
              </span>
            </label>
            <div className="scan-cap">
              <label className="field-label" htmlFor="scan-cap">
                MAX TARGETS
              </label>
                <input
                  id="scan-cap"
                  className="input input--num selectable"
                  type="number"
                  min={1}
                  max={200}
                  value={options.maxTargets}
                  onChange={(event) => set({ maxTargets: Number(event.target.value) || 24 })}
                />
            </div>
          </div>
    </Modal>
  );
};

export default ScanModal;
